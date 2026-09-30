//! CIDR range matching shared by the `latch-cidr-egress` and `latch-cidr-ingress` components.
//!
//! Without the `latch` feature this crate has no component bindings. With it, [`Reason`] converts
//! to the latch's sockets error code and [`Ranges::decision`] returns the latch's decision.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// What a latch does with a remote address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    // ordered so that deny sorts first when ranges are equally specific
    Deny,
    Defer,
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
    /// inclusive, `None` matches every port
    ports: Option<(u16, u16)>,
    action: Action,
}

impl Rule {
    /// Parse the rules for a config value, one rule for each port or port range in the value's
    /// port list, sharing a common network.
    fn parse(value: &str, action: Action, warnings: &mut Vec<String>) -> Result<Vec<Rule>, String> {
        let (network, ports) = parse_rule(value, warnings)?;
        Ok(ports
            .into_iter()
            .map(|ports| Rule {
                network,
                ports,
                action,
            })
            .collect())
    }

    /// The prefix length in the IPv6 address space, an IPv4 range is compared as the
    /// IPv4-mapped IPv6 range it represents.
    fn prefix_specificity(&self) -> u8 {
        match self.network {
            IpNet::V4(ipv4) => ipv4.prefix_len() + 96,
            IpNet::V6(ipv6) => ipv6.prefix_len(),
        }
    }

    /// The number of ports the rule matches, fewer is more specific.
    fn port_count(&self) -> u32 {
        match self.ports {
            Some((start, end)) => u32::from(end) - u32::from(start) + 1,
            None => u32::from(u16::MAX) + 1,
        }
    }

    /// Whether the rule matches a canonical address and port. An IPv6 range that contains the
    /// IPv4-mapped range, like `::/0`, also contains every IPv4 address.
    fn contains(&self, address: IpAddr, port: u16) -> bool {
        let address_matches = match (self.network, address) {
            (IpNet::V6(ipv6), IpAddr::V4(ipv4)) => ipv6.contains(&ipv4.to_ipv6_mapped()),
            (network, address) => network.contains(&address),
        };
        let port_matches = self
            .ports
            .is_none_or(|(start, end)| start <= port && port <= end);
        address_matches && port_matches
    }
}

/// Parse a CIDR range with an optional port list, e.g. `10.0.0.0/8`, `10.0.0.0/8:443`,
/// `10.1.2.3:80,443,8000-8999` or `[fd00::/8]:443`. An IPv6 range with a port list must be in
/// brackets. Without a port list, the range has a single rule matching every port. Without an
/// address, e.g. `:443`, the ports match every address.
fn parse_rule(
    value: &str,
    warnings: &mut Vec<String>,
) -> Result<(IpNet, Vec<Option<(u16, u16)>>), String> {
    let value = value.trim();
    let (network, ports) = if let Some(rest) = value.strip_prefix('[') {
        let (network, rest) = rest
            .split_once(']')
            .ok_or_else(|| "missing ']' after the address".to_string())?;
        match rest {
            "" => (network, None),
            _ => (
                network,
                Some(
                    rest.strip_prefix(':')
                        .ok_or_else(|| "expected ':' and a port range after ']'".to_string())?,
                ),
            ),
        }
    } else if value.matches(':').count() == 1 {
        // an IPv4 range and a port range, an IPv6 range has more than one ':'
        let (network, ports) = value.split_once(':').expect("value contains ':'");
        (network, Some(ports))
    } else {
        (value, None)
    };
    let network = match (network.trim(), ports) {
        // `::/0` contains every IPv6 address, and every IPv4 address in its IPv4-mapped form
        ("", Some(_)) => IpNet::V6(Ipv6Net::default()),
        (network, _) => parse_network(network, warnings)?,
    };
    let ports = match ports {
        Some(ports) => parse_port_list(ports)?.into_iter().map(Some).collect(),
        None => vec![None],
    };
    Ok((network, ports))
}

/// Parse a comma separated list of ports and port ranges, e.g. `80,443,8000-8999`.
fn parse_port_list(value: &str) -> Result<Vec<(u16, u16)>, String> {
    value
        .split(',')
        .map(|ports| match ports.trim() {
            "" => Err("empty entry in the port list".to_string()),
            ports => parse_ports(ports),
        })
        .collect()
}

/// Parse a single port, e.g. `443`, or an inclusive port range, e.g. `8000-8999`.
fn parse_ports(value: &str) -> Result<(u16, u16), String> {
    let (start, end) = value.split_once('-').unwrap_or((value, value));
    let port = |port: &str| {
        port.parse::<u16>()
            .map_err(|err| format!("invalid port {port:?}: {err}"))
    };
    let (start, end) = (port(start)?, port(end)?);
    if start > end {
        return Err(format!("port range {start}-{end} is empty"));
    }
    Ok((start, end))
}

/// Parse a CIDR range, a bare address is a range containing only that address. Bits set beyond
/// the prefix length are ignored with a warning, they are usually a mistake, e.g. `10.1.2.3/8`
/// for `10.1.2.3/32`.
fn parse_network(value: &str, warnings: &mut Vec<String>) -> Result<IpNet, String> {
    let value = value.trim();
    let network = if value.contains('/') {
        let network = value.parse::<IpNet>().map_err(|err| err.to_string())?;
        let truncated = network.trunc();
        if truncated != network {
            warnings.push(format!(
                "bits set beyond the prefix length are ignored, the range is {truncated}"
            ));
        }
        truncated
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

/// `deny*` and `defer*` CIDR ranges, with the `default` action and denial `reason`.
pub struct Ranges {
    /// most specific first
    rules: Vec<Rule>,
    reason: Reason,
    default: Action,
    warnings: Vec<String>,
}

impl Ranges {
    /// Parse the ranges from config key/value pairs, describing the offending entry on error as
    /// `KEY=<key> VALUE=<value> ERROR=<error>`. Entries that are accepted but likely mistakes are
    /// reported by [`Ranges::warnings`].
    pub fn parse(config: impl IntoIterator<Item = (String, String)>) -> Result<Ranges, String> {
        let mut rules: Vec<Rule> = vec![];
        let mut reason = Reason::AccessDenied;
        let mut default = Action::Defer;
        let mut warnings = vec![];

        // only the last value for a key is used, earlier values are overridden
        let config: Vec<(String, String)> = config.into_iter().collect();
        let last: HashMap<&str, usize> = config
            .iter()
            .enumerate()
            .map(|(index, (key, _))| (key.as_str(), index))
            .collect();

        for (index, (key, value)) in config.iter().enumerate() {
            if last[key.as_str()] != index {
                warnings.push(format!(
                    "KEY={key} VALUE={value} DETAIL=duplicate key is ignored, only the last value \
                     for the key is used"
                ));
                continue;
            }
            let invalid = |err: String| format!("KEY={key} VALUE={value} ERROR={err}");
            let mut value_warnings = vec![];
            if key.starts_with("deny") {
                rules.extend(
                    Rule::parse(&value, Action::Deny, &mut value_warnings).map_err(invalid)?,
                );
            } else if key.starts_with("defer") {
                rules.extend(
                    Rule::parse(&value, Action::Defer, &mut value_warnings).map_err(invalid)?,
                );
            } else if key == "reason" {
                reason = Reason::parse(value.clone());
            } else if key == "default" {
                default = match value.as_str() {
                    "deny" => Action::Deny,
                    "defer" => Action::Defer,
                    _ => return Err(invalid("expected 'deny' or 'defer'".to_string())),
                }
            } else {
                value_warnings.push(
                    "unknown key is ignored, expected a key starting with 'deny' or 'defer', \
                     'default' or 'reason'"
                        .to_string(),
                );
            }
            warnings.extend(
                value_warnings
                    .into_iter()
                    .map(|warning| format!("KEY={key} VALUE={value} DETAIL={warning}")),
            );
        }

        // the longest prefix is the most specific, then the fewest ports
        rules.sort_by(|a, b| {
            b.prefix_specificity()
                .cmp(&a.prefix_specificity())
                .then(a.port_count().cmp(&b.port_count()))
                .then(a.action.cmp(&b.action))
        });

        Ok(Ranges {
            rules,
            reason,
            default,
            warnings,
        })
    }

    /// The action for the address and port, from the most specific matching range or the
    /// default.
    pub fn action(&self, address: IpAddr, port: u16) -> Action {
        self.matching(address, port).unwrap_or(self.default)
    }

    /// The action of the most specific matching range.
    pub fn matching(&self, address: IpAddr, port: u16) -> Option<Action> {
        // IPv4-mapped IPv6 addresses must not bypass IPv4 ranges
        let address = address.to_canonical();

        self.rules
            .iter()
            .find(|rule| rule.contains(address, port))
            .map(|rule| rule.action)
    }

    /// The reason denials are reported with.
    pub fn reason(&self) -> &Reason {
        &self.reason
    }

    /// Config entries that were accepted but are likely mistakes, formatted as
    /// `KEY=<key> VALUE=<value> DETAIL=<warning>`.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

#[cfg(feature = "latch")]
mod latch {
    use std::net::IpAddr;

    use sockets_latch::{Decision, SocketsErrorCode};

    use crate::{Action, Ranges, Reason};

    impl From<&Reason> for SocketsErrorCode {
        fn from(reason: &Reason) -> SocketsErrorCode {
            match reason {
                Reason::AccessDenied => SocketsErrorCode::AccessDenied,
                Reason::InvalidArgument => SocketsErrorCode::InvalidArgument,
                Reason::Other(message) => SocketsErrorCode::Other(message.clone()),
            }
        }
    }

    impl Ranges {
        /// The latch decision for the address and port, denials are reported with the reason.
        pub fn decision(&self, address: IpAddr, port: u16) -> Decision {
            match self.action(address, port) {
                Action::Deny => Decision::Denied(self.reason().into()),
                Action::Defer => Decision::Deferred,
            }
        }
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

    /// An arbitrary port, for ranges without a port range.
    const PORT: u16 = 12345;

    fn matching(ranges: &Ranges, address: &str) -> Option<Action> {
        ranges.matching(address.parse().unwrap(), PORT)
    }

    fn matching_port(ranges: &Ranges, address: &str, port: u16) -> Option<Action> {
        ranges.matching(address.parse().unwrap(), port)
    }

    fn action(ranges: &Ranges, address: &str) -> Action {
        ranges.action(address.parse().unwrap(), PORT)
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
        let prefix = ranges(&[("deny", "::/80"), ("defer", "10.0.0.0/8")]);
        assert_eq!(matching(&prefix, "10.1.2.3"), Some(Action::Defer));
        assert_eq!(matching(&prefix, "11.1.2.3"), Some(Action::Deny));

        // 0.0.0.0/0 is ::ffff:0:0/96, more specific than ::/0
        let all = ranges(&[("defer", "::/0"), ("deny", "0.0.0.0/0")]);
        assert_eq!(matching(&all, "10.1.2.3"), Some(Action::Deny));
        assert_eq!(matching(&all, "2001:db8::1"), Some(Action::Defer));
    }

    #[test]
    fn mapped_and_ipv4_ranges_compare_by_ipv4_prefix() {
        let ranges = ranges(&[("deny", "10.0.0.0/8"), ("defer", "::ffff:10.1.0.0/112")]);
        assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Defer));
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
        let ranges = ranges(&[("deny", "10.0.0.0/8"), ("defer", "192.168.0.0/16")]);
        assert_eq!(matching(&ranges, "172.16.0.1"), None);
    }

    #[test]
    fn unrelated_keys_are_ignored() {
        let ranges = ranges(&[("other", "10.0.0.0/8")]);
        assert_eq!(matching(&ranges, "10.0.0.1"), None);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Defer);
    }

    #[test]
    fn longer_prefix_defer_overrides_shorter_deny() {
        for config in [
            [("deny", "10.0.0.0/8"), ("defer", "10.1.0.0/16")],
            [("defer", "10.1.0.0/16"), ("deny", "10.0.0.0/8")],
        ] {
            let ranges = ranges(&config);
            assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Defer));
            assert_eq!(matching(&ranges, "10.2.3.4"), Some(Action::Deny));
        }
    }

    #[test]
    fn longer_prefix_deny_overrides_shorter_defer() {
        for config in [
            [("defer", "10.0.0.0/8"), ("deny", "10.1.0.0/16")],
            [("deny", "10.1.0.0/16"), ("defer", "10.0.0.0/8")],
        ] {
            let ranges = ranges(&config);
            assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Deny));
            assert_eq!(matching(&ranges, "10.2.3.4"), Some(Action::Defer));
        }
    }

    #[test]
    fn nested_exceptions() {
        let ranges = ranges(&[
            ("deny-1", "10.0.0.0/8"),
            ("defer-1", "10.1.0.0/16"),
            ("deny-2", "10.1.2.3"),
        ]);
        assert_eq!(matching(&ranges, "10.2.0.1"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "10.1.0.1"), Some(Action::Defer));
        assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Deny));
    }

    #[test]
    fn deny_wins_when_equally_specific() {
        for config in [
            [("deny", "10.0.0.0/8"), ("defer", "10.0.0.0/8")],
            [("defer", "10.0.0.0/8"), ("deny", "10.0.0.0/8")],
        ] {
            let ranges = ranges(&config);
            assert_eq!(matching(&ranges, "10.1.2.3"), Some(Action::Deny));
        }
    }

    #[test]
    fn denies_with_access_denied_by_default() {
        let ranges = ranges(&[("deny", "10.0.0.0/8")]);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Deny);
        assert_eq!(action(&ranges, "192.0.2.1"), Action::Defer);
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
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Defer);
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
    fn default_defer() {
        let ranges = ranges(&[("default", "defer")]);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Defer);
    }

    #[test]
    fn matching_range_overrides_default() {
        let ranges = ranges(&[("default", "deny"), ("defer", "10.0.0.0/8")]);
        assert_eq!(action(&ranges, "10.0.0.1"), Action::Defer);
        assert_eq!(action(&ranges, "192.0.2.1"), Action::Deny);
    }

    #[test]
    fn unknown_default_is_invalid() {
        assert_eq!(
            parse(&[("default", "grant")]).err().unwrap(),
            "KEY=default VALUE=grant ERROR=expected 'deny' or 'defer'"
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

    #[test]
    fn port_range_on_ipv4_range() {
        let ranges = ranges(&[("deny", "10.0.0.0/8:8000-8999")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 8000), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "10.1.2.3", 8999), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "10.1.2.3", 7999), None);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 9000), None);
        assert_eq!(matching_port(&ranges, "11.1.2.3", 8000), None);
    }

    #[test]
    fn single_port_on_bare_address() {
        let ranges = ranges(&[("deny", "10.1.2.3:53")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 53), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "10.1.2.3", 54), None);
        assert_eq!(matching_port(&ranges, "10.1.2.4", 53), None);
    }

    #[test]
    fn port_range_on_ipv6_range_in_brackets() {
        let ranges = ranges(&[("deny-1", "[fd00::/8]:443"), ("deny-2", "[2001:db8::1]:53")]);
        assert_eq!(matching_port(&ranges, "fd12::1", 443), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "fd12::1", 80), None);
        assert_eq!(
            matching_port(&ranges, "2001:db8::1", 53),
            Some(Action::Deny)
        );
        assert_eq!(matching_port(&ranges, "2001:db8::1", 54), None);
    }

    #[test]
    fn ipv6_range_without_port_needs_no_brackets() {
        let bare = ranges(&[("deny", "fd00::/8")]);
        let bracketed = ranges(&[("deny", "[fd00::/8]")]);
        for ranges in [bare, bracketed] {
            assert_eq!(matching_port(&ranges, "fd12::1", 1), Some(Action::Deny));
            assert_eq!(matching_port(&ranges, "fd12::1", 65535), Some(Action::Deny));
        }
    }

    #[test]
    fn port_range_on_ipv4_mapped_range() {
        let ranges = ranges(&[("deny", "[::ffff:10.0.0.0/104]:443")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 443), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "10.1.2.3", 80), None);
    }

    #[test]
    fn full_port_range() {
        let ranges = ranges(&[("deny", "10.0.0.0/8:0-65535")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 0), Some(Action::Deny));
        assert_eq!(
            matching_port(&ranges, "10.1.2.3", 65535),
            Some(Action::Deny)
        );
    }

    #[test]
    fn address_prefix_decides_before_ports() {
        // the /16 is more specific than the /8, even though the /8 has a port range
        let ranges = ranges(&[("deny", "10.0.0.0/8:443"), ("defer", "10.1.0.0/16")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 443), Some(Action::Defer));
        assert_eq!(matching_port(&ranges, "10.2.3.4", 443), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "10.2.3.4", 80), None);
    }

    #[test]
    fn fewer_ports_decide_for_equal_prefixes() {
        for config in [
            [("defer", "10.0.0.0/8"), ("deny", "10.0.0.0/8:443")],
            [("deny", "10.0.0.0/8:443"), ("defer", "10.0.0.0/8")],
        ] {
            let ranges = ranges(&config);
            assert_eq!(matching_port(&ranges, "10.1.2.3", 443), Some(Action::Deny));
            assert_eq!(matching_port(&ranges, "10.1.2.3", 80), Some(Action::Defer));
        }

        let ranges = ranges(&[("deny", "10.0.0.0/8:1-1024"), ("defer", "10.0.0.0/8:22")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 22), Some(Action::Defer));
        assert_eq!(matching_port(&ranges, "10.1.2.3", 80), Some(Action::Deny));
    }

    #[test]
    fn deny_wins_for_equal_prefixes_and_ports() {
        let ranges = ranges(&[("defer", "10.0.0.0/8:443"), ("deny", "10.0.0.0/8:443")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 443), Some(Action::Deny));
    }

    #[test]
    fn port_list() {
        let ranges = ranges(&[("deny", "10.0.0.0/8:80,443,8000-8999")]);
        for port in [80, 443, 8000, 8500, 8999] {
            assert_eq!(
                matching_port(&ranges, "10.1.2.3", port),
                Some(Action::Deny),
                "{port}"
            );
        }
        for port in [79, 81, 442, 444, 7999, 9000] {
            assert_eq!(matching_port(&ranges, "10.1.2.3", port), None, "{port}");
        }
    }

    #[test]
    fn port_list_on_ipv6_range_in_brackets() {
        let ranges = ranges(&[("deny", "[fd00::/8]:80,443")]);
        assert_eq!(matching_port(&ranges, "fd12::1", 80), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "fd12::1", 443), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "fd12::1", 8080), None);
    }

    #[test]
    fn port_list_allows_whitespace() {
        let ranges = ranges(&[("deny", "10.0.0.0/8: 80 , 443 ")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 80), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "10.1.2.3", 443), Some(Action::Deny));
    }

    #[test]
    fn port_list_entries_are_separate_rules() {
        // each entry is as specific as its own ports, the single port is more specific than the
        // deferred range while the wide range in the same list is less specific
        let ranges = ranges(&[
            ("deny", "10.0.0.0/8:22,1000-2000"),
            ("defer", "10.0.0.0/8:1500-1600"),
        ]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 22), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "10.1.2.3", 1000), Some(Action::Deny));
        assert_eq!(
            matching_port(&ranges, "10.1.2.3", 1500),
            Some(Action::Defer)
        );
    }

    #[test]
    fn ports_without_address_match_every_address() {
        let ranges = ranges(&[("deny", ":80,443")]);
        for address in ["10.1.2.3", "192.0.2.1", "::ffff:10.1.2.3", "2001:db8::1"] {
            assert_eq!(
                matching_port(&ranges, address, 443),
                Some(Action::Deny),
                "{address}"
            );
            assert_eq!(
                matching_port(&ranges, address, 80),
                Some(Action::Deny),
                "{address}"
            );
            assert_eq!(matching_port(&ranges, address, 8080), None, "{address}");
        }
    }

    #[test]
    fn ports_without_address_are_the_least_specific_address() {
        // any range with an address is more specific, regardless of its ports
        let ranges = ranges(&[("deny", ":22"), ("defer", "10.0.0.0/8")]);
        assert_eq!(matching_port(&ranges, "10.1.2.3", 22), Some(Action::Defer));
        assert_eq!(matching_port(&ranges, "11.1.2.3", 22), Some(Action::Deny));
        assert_eq!(matching_port(&ranges, "11.1.2.3", 80), None);
    }

    /// The worked example in the latch-cidr-egress and latch-cidr-ingress READMEs.
    #[test]
    fn readme_precedence_example() {
        let ranges = ranges(&[
            ("defer-1", "0.0.0.0/0:443"),
            ("deny-1", "10.0.0.0/8"),
            ("defer-2", "10.1.0.0/16"),
            ("deny-2", "10.1.2.3:22"),
            ("deny-3", ":25"),
        ]);
        for (address, port, expected) in [
            ("192.0.2.1", 443, Action::Defer),
            ("192.0.2.1", 25, Action::Deny),
            ("192.0.2.1", 80, Action::Defer),
            ("10.2.0.1", 443, Action::Deny),
            ("10.1.0.1", 25, Action::Defer),
            ("10.1.2.3", 22, Action::Deny),
            ("10.1.2.3", 80, Action::Defer),
            ("2001:db8::1", 25, Action::Deny),
            ("2001:db8::1", 443, Action::Defer),
            ("::ffff:10.2.0.1", 443, Action::Deny),
        ] {
            assert_eq!(
                ranges.action(address.parse().unwrap(), port),
                expected,
                "{address} port {port}"
            );
        }
        // the example relies on the default for these
        assert_eq!(ranges.matching("192.0.2.1".parse().unwrap(), 80), None);
        assert_eq!(ranges.matching("2001:db8::1".parse().unwrap(), 443), None);
    }

    #[test]
    fn unknown_keys_are_warned() {
        let ranges = ranges(&[("deni-1", "10.0.0.0/8"), ("Deny-2", "10.0.0.0/8")]);
        assert_eq!(matching(&ranges, "10.1.2.3"), None);
        assert_eq!(
            ranges.warnings(),
            [
                "KEY=deni-1 VALUE=10.0.0.0/8 DETAIL=unknown key is ignored, expected a key \
                 starting with 'deny' or 'defer', 'default' or 'reason'",
                "KEY=Deny-2 VALUE=10.0.0.0/8 DETAIL=unknown key is ignored, expected a key \
                 starting with 'deny' or 'defer', 'default' or 'reason'",
            ]
        );
    }

    #[test]
    fn host_bits_are_warned() {
        let ranges = ranges(&[
            ("deny-1", "10.1.2.3/8:443"),
            ("deny-2", "[2001:db8::1/32]"),
            ("deny-3", "[::ffff:10.1.2.3/104]"),
        ]);
        assert_eq!(
            ranges.warnings(),
            [
                "KEY=deny-1 VALUE=10.1.2.3/8:443 DETAIL=bits set beyond the prefix length are \
                 ignored, the range is 10.0.0.0/8",
                "KEY=deny-2 VALUE=[2001:db8::1/32] DETAIL=bits set beyond the prefix length are \
                 ignored, the range is 2001:db8::/32",
                "KEY=deny-3 VALUE=[::ffff:10.1.2.3/104] DETAIL=bits set beyond the prefix length \
                 are ignored, the range is ::ffff:10.0.0.0/104",
            ]
        );
    }

    #[test]
    fn duplicate_keys_use_the_last_value() {
        let ranges = ranges(&[
            ("deny-1", "10.0.0.0/8"),
            ("defer-1", "192.168.0.0/16"),
            ("deny-1", "172.16.0.0/12"),
        ]);
        // only the last deny-1 is active
        assert_eq!(matching(&ranges, "10.1.2.3"), None);
        assert_eq!(matching(&ranges, "172.16.1.2"), Some(Action::Deny));
        assert_eq!(matching(&ranges, "192.168.1.2"), Some(Action::Defer));
        assert_eq!(
            ranges.warnings(),
            [
                "KEY=deny-1 VALUE=10.0.0.0/8 DETAIL=duplicate key is ignored, only the last value \
              for the key is used"
            ]
        );
    }

    #[test]
    fn duplicate_default_and_reason_use_the_last_value() {
        // an overridden invalid value is not an error, it is never used
        let ranges = ranges(&[
            ("default", "grant"),
            ("reason", "invalid-argument"),
            ("default", "deny"),
            ("reason", "access-denied"),
        ]);
        assert_eq!(action(&ranges, "10.1.2.3"), Action::Deny);
        assert_eq!(ranges.reason(), &Reason::AccessDenied);
        assert_eq!(ranges.warnings().len(), 2);
    }

    #[test]
    fn valid_config_has_no_warnings() {
        let ranges = ranges(&[
            ("deny", "10.0.0.0/8"),
            ("defer", "10.1.2.3"),
            ("deny-ports", ":22"),
            ("default", "deny"),
            ("reason", "invalid-argument"),
        ]);
        assert!(ranges.warnings().is_empty(), "{:?}", ranges.warnings());
    }

    #[test]
    fn invalid_port_range_is_invalid() {
        for value in [
            "10.0.0.0/8:",
            "10.0.0.0/8:65536",
            "10.0.0.0/8:http",
            "10.0.0.0/8:9000-8000",
            "10.0.0.0/8:1-2-3",
            "10.0.0.0/8:80,",
            "10.0.0.0/8:,80",
            "10.0.0.0/8:80,,443",
            "10.0.0.0/8:80,http",
            "10.0.0.0/8:80;443",
            ":",
            ":http",
            "[fd00::/8",
            "[fd00::/8]443",
            "[fd00::/8]:",
        ] {
            let err = parse(&[("deny", value)])
                .err()
                .unwrap_or_else(|| panic!("{value:?} should be invalid"));
            assert!(
                err.starts_with(&format!("KEY=deny VALUE={value} ERROR=")),
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
