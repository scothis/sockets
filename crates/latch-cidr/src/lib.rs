//! CIDR range matching shared by the `latch-cidr-egress` and `latch-cidr-ingress` components.
//!
//! This crate has no component bindings, latches map [`Action`] and [`Reason`] to their own
//! generated types.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use ipnet::{IpNet, Ipv4Net};

/// What a latch does with a remote address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    // ordered so that deny sorts first when ranges are equally specific
    Deny,
    Abstain,
}

/// The sockets error code a denial is reported with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    AccessDenied,
    InvalidArgument,
    Other(Option<String>),
}

impl Reason {
    fn parse(value: String) -> Reason {
        match value.as_str() {
            "" | "access-denied" => Reason::AccessDenied,
            "invalid-argument" => Reason::InvalidArgument,
            "other" => Reason::Other(None),
            _ => Reason::Other(Some(value)),
        }
    }
}

struct Rule {
    network: IpNet,
    action: Action,
}

impl Rule {
    fn new(value: &str, action: Action) -> Result<Rule, String> {
        Ok(Rule {
            network: parse_network(value)?,
            action,
        })
    }

    /// The prefix length in the IPv6 address space, an IPv4 range is compared as the
    /// IPv4-mapped IPv6 range it represents.
    fn specificity(&self) -> u8 {
        match self.network {
            IpNet::V4(ipv4) => ipv4.prefix_len() + 96,
            IpNet::V6(ipv6) => ipv6.prefix_len(),
        }
    }

    /// Whether the range contains a canonical address. An IPv6 range that contains the
    /// IPv4-mapped range, like `::/0`, also contains every IPv4 address.
    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpNet::V6(ipv6), IpAddr::V4(ipv4)) => ipv6.contains(&ipv4.to_ipv6_mapped()),
            (network, address) => network.contains(&address),
        }
    }
}

/// Parse a CIDR range, a bare address is a range containing only that address.
fn parse_network(value: &str) -> Result<IpNet, String> {
    let value = value.trim();
    let network = if value.contains('/') {
        value
            .parse::<IpNet>()
            .map(|network| network.trunc())
            .map_err(|err| err.to_string())?
    } else {
        value
            .parse::<IpAddr>()
            .map(IpNet::from)
            .map_err(|err| err.to_string())?
    };
    Ok(canonical_network(network))
}

/// Convert an IPv4-mapped IPv6 range to the IPv4 range it represents, the same as addresses are
/// converted before matching. Wider IPv6 ranges, like `::/0`, remain IPv6.
fn canonical_network(network: IpNet) -> IpNet {
    match network {
        IpNet::V6(ipv6) if ipv6.prefix_len() >= 96 => match ipv6.addr().to_ipv4_mapped() {
            Some(ipv4) => IpNet::V4(
                Ipv4Net::new(ipv4, ipv6.prefix_len() - 96).expect("prefix length is at most 32"),
            ),
            None => network,
        },
        _ => network,
    }
}

/// `deny*` and `abstain*` CIDR ranges, with the `default` action and denial `reason`.
pub struct Ranges {
    /// most specific first
    rules: Vec<Rule>,
    reason: Reason,
    default: Action,
}

impl Ranges {
    /// Parse the ranges from config key/value pairs, describing the offending entry on error as
    /// `KEY=<key> VALUE=<value> ERROR=<error>`.
    pub fn parse(config: impl IntoIterator<Item = (String, String)>) -> Result<Ranges, String> {
        let mut rules: Vec<Rule> = vec![];
        let mut reason = Reason::AccessDenied;
        let mut default = Action::Abstain;

        for (key, value) in config {
            let invalid = |err: String| format!("KEY={key} VALUE={value} ERROR={err}");
            if key.starts_with("deny") {
                rules.push(Rule::new(&value, Action::Deny).map_err(invalid)?);
            } else if key.starts_with("abstain") {
                rules.push(Rule::new(&value, Action::Abstain).map_err(invalid)?);
            } else if key == "reason" {
                reason = Reason::parse(value);
            } else if key == "default" {
                default = match value.as_str() {
                    "deny" => Action::Deny,
                    "abstain" => Action::Abstain,
                    _ => return Err(invalid("expected 'deny' or 'abstain'".to_string())),
                }
            }
        }

        // the longest prefix is the most specific
        rules.sort_by(|a, b| {
            b.specificity()
                .cmp(&a.specificity())
                .then(a.action.cmp(&b.action))
        });

        Ok(Ranges {
            rules,
            reason,
            default,
        })
    }

    /// The action for the address, from the most specific matching range or the default.
    pub fn action(&self, address: IpAddr) -> Action {
        self.matching(address).unwrap_or(self.default)
    }

    /// The action of the most specific matching range.
    pub fn matching(&self, address: IpAddr) -> Option<Action> {
        // IPv4-mapped IPv6 addresses must not bypass IPv4 ranges
        let address = address.to_canonical();

        self.rules
            .iter()
            .find(|rule| rule.contains(address))
            .map(|rule| rule.action)
    }

    /// The reason denials are reported with.
    pub fn reason(&self) -> &Reason {
        &self.reason
    }
}

/// Remote peers a socket has exchanged traffic with, keyed by the socket's local address.
///
/// Sockets are identified by their local address, since resource handles are not stable across
/// latch calls. A peer recorded without a local address, for a socket that was not yet bound,
/// matches every local address. Entries do not expire, most component executions are short
/// lived.
pub struct Peers(BTreeSet<(Option<SocketAddr>, SocketAddr)>);

impl Peers {
    pub const fn new() -> Peers {
        Peers(BTreeSet::new())
    }

    pub fn record(&mut self, local_address: Option<SocketAddr>, remote_address: SocketAddr) {
        self.0.insert((
            local_address.map(canonical_socket_addr),
            canonical_socket_addr(remote_address),
        ));
    }

    pub fn contains(&self, local_address: Option<SocketAddr>, remote_address: SocketAddr) -> bool {
        let remote_address = canonical_socket_addr(remote_address);
        local_address.is_some_and(|local_address| {
            self.0
                .contains(&(Some(canonical_socket_addr(local_address)), remote_address))
        }) || self.0.contains(&(None, remote_address))
    }
}

impl Default for Peers {
    fn default() -> Self {
        Peers::new()
    }
}

/// An IPv4 peer may be reported in its IPv4-mapped IPv6 form.
fn canonical_socket_addr(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(config: &[(&str, &str)]) -> Result<Ranges, String> {
        Ranges::parse(config.iter().map(|(k, v)| (k.to_string(), v.to_string())))
    }

    fn ranges(config: &[(&str, &str)]) -> Ranges {
        parse(config).expect("valid config")
    }

    fn matching(ranges: &Ranges, address: &str) -> Option<Action> {
        ranges.matching(address.parse().unwrap())
    }

    fn action(ranges: &Ranges, address: &str) -> Action {
        ranges.action(address.parse().unwrap())
    }

    #[test]
    fn ipv4_range() {
        let ranges = ranges(&[("deny", "10.0.0.0/8")]);
        assert_eq!(matching(&ranges, "10.0.0.0"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "10.255.255.255"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "11.0.0.0"), None);
        assert_eq!(matching(&ranges, "9.255.255.255"), None);
    }

    #[test]
    fn ipv6_range() {
        let ranges = ranges(&[("deny", "fd00::/8")]);
        assert_eq!(matching(&ranges, "fd12:3456::1"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "fe80::1"), None);
    }

    #[test]
    fn ipv4_ranges_only_match_ipv4_addresses() {
        let ranges = ranges(&[("deny", "0.0.0.0/0")]);
        assert_eq!(matching(&ranges, "192.0.2.1"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "2001:db8::1"), None);
    }

    #[test]
    fn ipv6_ranges_outside_the_mapped_range_do_not_match_ipv4() {
        let ranges = ranges(&[("deny-1", "2001:db8::/32"), ("deny-2", "::/97")]);
        assert_eq!(matching(&ranges, "2001:db8::1"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "::1"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "10.1.2.3"), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_ranges() {
        let ranges = ranges(&[("deny", "10.0.0.0/8")]);
        assert_eq!(matching(&ranges, "::ffff:10.1.2.3"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "::ffff:11.1.2.3"), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_ranges_match_ipv4_addresses() {
        // the prefix length of an IPv6 range counts all 128 bits, /104 is 96 + 8
        let ranges = ranges(&[("deny", "::ffff:10.0.0.0/104")]);
        assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "::ffff:10.1.2.3"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "11.1.2.3"), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_bare_address_matches_ipv4_address() {
        let ranges = ranges(&[("deny", "::ffff:10.1.2.3")]);
        assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "10.1.2.4"), None);
    }

    #[test]
    fn ipv6_ranges_containing_the_mapped_range_match_ipv4() {
        for value in ["::/0", "::/80", "::ffff:0:0/96"] {
            let mapped = ranges(&[("deny", value)]);
            assert_eq!(matching(&mapped, "10.1.2.3"), Some(Action::Deny), "{value}");
            assert_eq!(
                matching(&mapped, "::ffff:10.1.2.3"),
                Some(Action::Deny),
                "{value}"
            );
        }
        let ranges = ranges(&[("deny", "::/0")]);
        assert_eq!(matching(&ranges, "2001:db8::1"), Some(Action::Deny));
    }

    #[test]
    fn ipv4_ranges_compare_as_ipv4_mapped_ipv6_ranges() {
        // 10.0.0.0/8 is ::ffff:10.0.0.0/104, more specific than ::/80
        let prefix = ranges(&[("deny", "::/80"), ("abstain", "10.0.0.0/8")]);
        assert_eq!(matching(&prefix, "10.1.2.3"), Some(Action::Abstain));
        assert_eq!(matching(&prefix, "11.1.2.3"), Some(Action::Deny));

        // 0.0.0.0/0 is ::ffff:0:0/96, more specific than ::/0
        let all = ranges(&[("abstain", "::/0"), ("deny", "0.0.0.0/0")]);
        assert_eq!(matching(&all, "10.1.2.3"), Some(Action::Deny));
        assert_eq!(matching(&all, "2001:db8::1"), Some(Action::Abstain));
    }

    #[test]
    fn mapped_and_ipv4_ranges_compare_by_ipv4_prefix() {
        let ranges = ranges(&[("deny", "10.0.0.0/8"), ("abstain", "::ffff:10.1.0.0/112")]);
        assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Abstain));
        assert_eq!(matching(&ranges, "10.2.3.4"), Some(Action::Deny));
    }

    #[test]
    fn bare_address_is_a_single_host() {
        let ranges = ranges(&[("deny-1", "192.0.2.1"), ("deny-2", "2001:db8::1")]);
        assert_eq!(matching(&ranges, "192.0.2.1"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "192.0.2.2"), None);
        assert_eq!(matching(&ranges, "2001:db8::1"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "2001:db8::2"), None);
    }

    #[test]
    fn host_bits_are_ignored() {
        let ranges = ranges(&[("deny", "10.1.2.3/8")]);
        assert_eq!(matching(&ranges, "10.200.0.1"), Some(Action::Deny));
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let ranges = ranges(&[("deny", " 10.0.0.0/8 ")]);
        assert_eq!(matching(&ranges, "10.0.0.1"), Some(Action::Deny));
    }

    #[test]
    fn unmatched_address_has_no_action() {
        let ranges = ranges(&[("deny", "10.0.0.0/8"), ("abstain", "192.168.0.0/16")]);
        assert_eq!(matching(&ranges, "172.16.0.1"), None);
    }

    #[test]
    fn unrelated_keys_are_ignored() {
        let ranges = ranges(&[("other", "10.0.0.0/8")]);
        assert_eq!(matching(&ranges, "10.0.0.1"), None);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Abstain);
    }

    #[test]
    fn longer_prefix_abstain_overrides_shorter_deny() {
        for config in [
            [("deny", "10.0.0.0/8"), ("abstain", "10.1.0.0/16")],
            [("abstain", "10.1.0.0/16"), ("deny", "10.0.0.0/8")],
        ] {
            let ranges = ranges(&config);
            assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Abstain));
            assert_eq!(matching(&ranges, "10.2.3.4"), Some(Action::Deny));
        }
    }

    #[test]
    fn longer_prefix_deny_overrides_shorter_abstain() {
        for config in [
            [("abstain", "10.0.0.0/8"), ("deny", "10.1.0.0/16")],
            [("deny", "10.1.0.0/16"), ("abstain", "10.0.0.0/8")],
        ] {
            let ranges = ranges(&config);
            assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Deny));
            assert_eq!(matching(&ranges, "10.2.3.4"), Some(Action::Abstain));
        }
    }

    #[test]
    fn nested_exceptions() {
        let ranges = ranges(&[
            ("deny-1", "10.0.0.0/8"),
            ("abstain-1", "10.1.0.0/16"),
            ("deny-2", "10.1.2.3"),
        ]);
        assert_eq!(matching(&ranges, "10.2.0.1"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "10.1.0.1"), Some(Action::Abstain));
        assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Deny));
    }

    #[test]
    fn deny_wins_when_equally_specific() {
        for config in [
            [("deny", "10.0.0.0/8"), ("abstain", "10.0.0.0/8")],
            [("abstain", "10.0.0.0/8"), ("deny", "10.0.0.0/8")],
        ] {
            let ranges = ranges(&config);
            assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Deny));
        }
    }

    #[test]
    fn denies_with_access_denied_by_default() {
        let ranges = ranges(&[("deny", "10.0.0.0/8")]);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Deny);
        assert_eq!(action(&ranges, "192.0.2.1"), Action::Abstain);
        assert_eq!(ranges.reason(), &Reason::AccessDenied);
    }

    #[test]
    fn configured_reason() {
        for (value, expected) in [
            ("access-denied", Reason::AccessDenied),
            ("invalid-argument", Reason::InvalidArgument),
            ("other", Reason::Other(None)),
            ("", Reason::AccessDenied),
            (
                "custom-reason",
                Reason::Other(Some("custom-reason".to_string())),
            ),
        ] {
            let ranges = ranges(&[("reason", value)]);
            assert_eq!(ranges.reason(), &expected, "reason={value}");
        }
    }

    #[test]
    fn reason_does_not_change_the_default() {
        let ranges = ranges(&[("reason", "invalid-argument")]);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Abstain);
    }

    #[test]
    fn default_deny_regardless_of_order() {
        for config in [
            [("reason", "invalid-argument"), ("default", "deny")],
            [("default", "deny"), ("reason", "invalid-argument")],
        ] {
            let ranges = ranges(&config);
            assert_eq!(action(&ranges, "10.0.0.1"), Action::Deny);
            assert_eq!(ranges.reason(), &Reason::InvalidArgument);
        }
    }

    #[test]
    fn default_abstain() {
        let ranges = ranges(&[("default", "abstain")]);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Abstain);
    }

    #[test]
    fn matching_range_overrides_default() {
        let ranges = ranges(&[("default", "deny"), ("abstain", "10.0.0.0/8")]);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Abstain);
        assert_eq!(action(&ranges, "192.0.2.1"), Action::Deny);
    }

    #[test]
    fn unknown_default_is_invalid() {
        assert_eq!(
            parse(&[("default", "grant")]).err().unwrap(),
            "KEY=default VALUE=grant ERROR=expected 'deny' or 'abstain'"
        );
    }

    #[test]
    fn invalid_range_is_invalid() {
        for value in ["10.0.0.0/33", "fd00::/129", "10.0.0/8", "example.com", ""] {
            let err = parse(&[("deny-1", "10.0.0.0/8"), ("deny-2", value)])
                .err()
                .unwrap_or_else(|| panic!("{value:?} should be invalid"));
            assert!(
                err.starts_with(&format!("KEY=deny-2 VALUE={value} ERROR=")),
                "{err}"
            );
        }
    }

    fn addr(address: &str) -> SocketAddr {
        address.parse().unwrap()
    }

    #[test]
    fn peers_match_on_local_and_remote_address() {
        let mut peers = Peers::new();
        peers.record(Some(addr("127.0.0.1:5000")), addr("192.0.2.1:53"));
        assert!(peers.contains(Some(addr("127.0.0.1:5000")), addr("192.0.2.1:53")));
        assert!(peers.contains(Some(addr("127.0.0.1:5000")), addr("[::ffff:192.0.2.1]:53")));
        assert!(!peers.contains(Some(addr("127.0.0.1:5000")), addr("192.0.2.1:54")));
        assert!(!peers.contains(Some(addr("127.0.0.1:5000")), addr("192.0.2.2:53")));
        assert!(!peers.contains(Some(addr("127.0.0.1:5001")), addr("192.0.2.1:53")));
        assert!(!peers.contains(None, addr("192.0.2.1:53")));
    }

    #[test]
    fn peers_recorded_without_local_address_match_any_socket() {
        let mut peers = Peers::new();
        peers.record(None, addr("192.0.2.1:53"));
        assert!(peers.contains(Some(addr("127.0.0.1:5000")), addr("192.0.2.1:53")));
        assert!(peers.contains(None, addr("192.0.2.1:53")));
        assert!(!peers.contains(Some(addr("127.0.0.1:5000")), addr("192.0.2.1:54")));
    }
}
