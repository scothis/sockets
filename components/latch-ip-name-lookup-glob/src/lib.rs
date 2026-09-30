use glob::{MatchOptions, Pattern};
use std::path::Path;

use sockets_latch::{
    Decision, ErrorCode, IpNameLookupOperation, Latch, Local, Operation, SocketsErrorCode,
};

const LATCH_NAME: &str = "latch-ip-name-lookup-glob";

struct GlobIpNameLookupLatch {}

// labels are mapped to path segments, a single `*` must not match across labels
const MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: false,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Action {
    // ordered so that deny sorts first when patterns are equally specific
    Deny,
    Defer,
}

struct Rule {
    pattern: Pattern,
    specificity: Vec<(u8, usize)>,
    action: Action,
}

impl Rule {
    fn new(pattern: &str, action: Action) -> Result<Rule, String> {
        Ok(Rule {
            pattern: Pattern::new(&pattern.replace(".", "/")).map_err(|err| err.to_string())?,
            specificity: specificity(pattern),
            action,
        })
    }
}

/// Rank each label of a pattern, starting with the top level label.
///
/// Rankings compare label by label, the first label that differs decides which pattern is more
/// specific. Within a label, a literal beats a partial wildcard (more literal characters win),
/// which beats `*`, which beats `**`.
fn specificity(pattern: &str) -> Vec<(u8, usize)> {
    pattern
        .rsplit('.')
        .map(|label| match label {
            "**" => (0, 0),
            "*" => (2, 0),
            _ if label.contains(['*', '?', '[']) => (3, literal_chars(label)),
            _ => (4, label.len()),
        })
        .collect()
}

/// A pattern that has no more labels only matches when the name also has no more labels, which is
/// more specific than `**` but less specific than any other label.
const END_OF_PATTERN: (u8, usize) = (1, 0);

fn literal_chars(label: &str) -> usize {
    let mut count = 0;
    let mut in_class = false;
    for c in label.chars() {
        match c {
            '[' => in_class = true,
            ']' => in_class = false,
            '*' | '?' => {}
            _ if !in_class => count += 1,
            _ => {}
        }
    }
    count
}

fn compare_specificity(a: &[(u8, usize)], b: &[(u8, usize)]) -> std::cmp::Ordering {
    (0..a.len().max(b.len()))
        .map(|i| {
            let a = a.get(i).unwrap_or(&END_OF_PATTERN);
            let b = b.get(i).unwrap_or(&END_OF_PATTERN);
            a.cmp(b)
        })
        .find(|ordering| ordering.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

struct Patterns {
    /// most specific first
    rules: Vec<Rule>,
    reason: SocketsErrorCode,
    default: Action,
}

impl Patterns {
    /// Load the patterns from config, logging why when the config is invalid.
    fn load() -> Result<Patterns, ErrorCode> {
        sockets_latch::load_config(LATCH_NAME, Patterns::parse)
    }

    fn parse(config: Vec<(String, String)>) -> Result<Patterns, String> {
        let mut rules: Vec<Rule> = vec![];
        let mut reason = SocketsErrorCode::AccessDenied;
        let mut default = Action::Defer;

        for (key, value) in config {
            let invalid = |err: String| format!("KEY={key} VALUE={value} ERROR={err}");
            if key.starts_with("deny") {
                rules.push(Rule::new(&value, Action::Deny).map_err(invalid)?);
            } else if key.starts_with("defer") {
                rules.push(Rule::new(&value, Action::Defer).map_err(invalid)?);
            } else if key == "reason" {
                reason = get_error_code(value).unwrap_or(SocketsErrorCode::AccessDenied);
            } else if key == "default" {
                default = match value.as_str() {
                    "deny" => Action::Deny,
                    "defer" => Action::Defer,
                    _ => return Err(invalid("expected 'deny' or 'defer'".to_string())),
                }
            }
        }

        rules.sort_by(|a, b| {
            compare_specificity(&b.specificity, &a.specificity).then(a.action.cmp(&b.action))
        });

        Ok(Patterns {
            rules,
            reason,
            default,
        })
    }

    fn authorize(name: String) -> Result<Decision, ErrorCode> {
        // config is loaded once, an invalid config fails every authorization
        match STATE.borrow_mut().get_or_insert_with(Patterns::load) {
            Ok(patterns) => Ok(patterns.decide(name)),
            Err(err) => Err(err.clone()),
        }
    }

    fn decide(&self, name: String) -> Decision {
        let action = self.authorize_name(name).unwrap_or(self.default);
        self.decision(action)
    }

    fn decision(&self, action: Action) -> Decision {
        match action {
            Action::Deny => Decision::Denied(self.reason.clone()),
            Action::Defer => Decision::Deferred,
        }
    }

    /// The action of the most specific matching pattern.
    fn authorize_name(&self, name: String) -> Option<Action> {
        let name = name.replace(".", "/");
        let name = Path::new(&name);

        self.rules
            .iter()
            .find(|rule| rule.pattern.matches_path_with(name, MATCH_OPTIONS))
            .map(|rule| rule.action)
    }
}

/// `None` until the config is loaded.
static STATE: Local<Option<Result<Patterns, ErrorCode>>> = Local::new(None);

impl Latch for GlobIpNameLookupLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::IpNameLookup(ip_name_lookup_operation) => match ip_name_lookup_operation {
                IpNameLookupOperation::ResolveAddresses(resolve_addresses_args) => {
                    Patterns::authorize(resolve_addresses_args.name)
                }
                IpNameLookupOperation::ResolveAddressesReturn(_) => Ok(Decision::Deferred),
            },
            _ => Ok(Decision::Deferred),
        }
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        // no side effects
        Ok(())
    }
}

fn get_error_code(value: String) -> Option<SocketsErrorCode> {
    match value.as_str() {
        "" => None,
        "access-denied" => Some(SocketsErrorCode::AccessDenied),
        "invalid-argument" => Some(SocketsErrorCode::InvalidArgument),
        "other" => Some(SocketsErrorCode::Other(None)),
        _ => Some(SocketsErrorCode::Other(Some(value))),
    }
}

sockets_latch::export!(GlobIpNameLookupLatch with_types_in sockets_latch::bindings);

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(config: &[(&str, &str)]) -> Result<Patterns, String> {
        Patterns::parse(
            config
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    fn patterns(config: &[(&str, &str)]) -> Patterns {
        parse(config).expect("valid config")
    }

    fn action(patterns: &Patterns, name: &str) -> Option<Action> {
        patterns.authorize_name(name.to_string())
    }

    fn is_denied(patterns: &Patterns, name: &str) -> bool {
        action(patterns, name) == Some(Action::Deny)
    }

    fn decision(patterns: &Patterns, name: &str) -> String {
        format!("{:?}", patterns.decide(name.to_string()))
    }

    fn denied(reason: SocketsErrorCode) -> String {
        format!("{:?}", Decision::Denied(reason))
    }

    fn deferred() -> String {
        format!("{:?}", Decision::Deferred)
    }

    #[test]
    fn single_star_matches_within_a_label() {
        let patterns = patterns(&[("deny", "*.com")]);
        assert!(is_denied(&patterns, "apple.com"));
        assert!(!is_denied(&patterns, "www.apple.com"));
        assert!(!is_denied(&patterns, "wikipedia.org"));
    }

    #[test]
    fn double_star_spans_labels() {
        let patterns = patterns(&[("deny", "**.com")]);
        assert!(is_denied(&patterns, "apple.com"));
        assert!(is_denied(&patterns, "www.apple.com"));
        assert!(!is_denied(&patterns, "wikipedia.org"));
    }

    #[test]
    fn literal_pattern_matches_exact_name() {
        let patterns = patterns(&[("deny", "apple.com")]);
        assert!(is_denied(&patterns, "apple.com"));
        assert!(!is_denied(&patterns, "www.apple.com"));
        assert!(!is_denied(&patterns, "apple.co"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let patterns = patterns(&[("deny", "*.Apple.COM")]);
        assert!(is_denied(&patterns, "WWW.apple.com"));
        assert!(is_denied(&patterns, "www.APPLE.com"));
    }

    #[test]
    fn multiple_deny_keys() {
        let patterns = patterns(&[("deny-1", "*.com"), ("deny-2", "*.org")]);
        assert!(is_denied(&patterns, "apple.com"));
        assert!(is_denied(&patterns, "wikipedia.org"));
        assert!(!is_denied(&patterns, "example.net"));
    }

    #[test]
    fn unmatched_name_has_no_action() {
        let patterns = patterns(&[("deny", "*.com"), ("defer", "*.org")]);
        assert_eq!(action(&patterns, "example.net"), None);
    }

    #[test]
    fn unrelated_keys_are_ignored() {
        let patterns = patterns(&[("other", "*.com")]);
        assert_eq!(action(&patterns, "apple.com"), None);
        assert_eq!(decision(&patterns, "apple.com"), deferred());
    }

    #[test]
    fn more_specific_defer_overrides_general_deny() {
        for config in [
            [("deny", "**.com"), ("defer", "*.apple.com")],
            [("defer", "*.apple.com"), ("deny", "**.com")],
        ] {
            let patterns = patterns(&config);
            assert_eq!(action(&patterns, "www.apple.com"), Some(Action::Defer));
            assert_eq!(action(&patterns, "www.example.com"), Some(Action::Deny));
        }
    }

    #[test]
    fn more_specific_deny_overrides_general_defer() {
        for config in [
            [("defer", "**.com"), ("deny", "*.apple.com")],
            [("deny", "*.apple.com"), ("defer", "**.com")],
        ] {
            let patterns = patterns(&config);
            assert_eq!(action(&patterns, "www.apple.com"), Some(Action::Deny));
            assert_eq!(action(&patterns, "apple.com"), Some(Action::Defer));
        }
    }

    #[test]
    fn nested_exceptions() {
        let patterns = patterns(&[
            ("deny-1", "**.com"),
            ("defer-1", "**.apple.com"),
            ("deny-2", "secret.apple.com"),
        ]);
        assert_eq!(action(&patterns, "example.com"), Some(Action::Deny));
        assert_eq!(action(&patterns, "www.apple.com"), Some(Action::Defer));
        assert_eq!(action(&patterns, "secret.apple.com"), Some(Action::Deny));
    }

    #[test]
    fn labels_closer_to_the_root_are_more_significant() {
        // `apple` is a literal where the other pattern has a wildcard
        let patterns = patterns(&[("deny", "www.*.com"), ("defer", "*.apple.com")]);
        assert_eq!(action(&patterns, "www.apple.com"), Some(Action::Defer));
    }

    #[test]
    fn literal_label_beats_wildcards() {
        let star = patterns(&[("deny", "*.com"), ("defer", "apple.com")]);
        assert_eq!(action(&star, "apple.com"), Some(Action::Defer));
        assert_eq!(action(&star, "example.com"), Some(Action::Deny));

        let partial = patterns(&[("deny", "app*.com"), ("defer", "apple.com")]);
        assert_eq!(action(&partial, "apple.com"), Some(Action::Defer));
        assert_eq!(action(&partial, "application.com"), Some(Action::Deny));
    }

    #[test]
    fn partial_wildcard_beats_single_star() {
        let patterns = patterns(&[("deny", "*.com"), ("defer", "app*.com")]);
        assert_eq!(action(&patterns, "apple.com"), Some(Action::Defer));
        assert_eq!(action(&patterns, "example.com"), Some(Action::Deny));
    }

    #[test]
    fn partial_wildcard_with_more_literals_wins() {
        let patterns = patterns(&[("deny", "a*.com"), ("defer", "app*.com")]);
        assert_eq!(action(&patterns, "apple.com"), Some(Action::Defer));
        assert_eq!(action(&patterns, "amazon.com"), Some(Action::Deny));
    }

    #[test]
    fn single_star_beats_double_star() {
        let patterns = patterns(&[("deny", "**.com"), ("defer", "*.com")]);
        assert_eq!(action(&patterns, "apple.com"), Some(Action::Defer));
        assert_eq!(action(&patterns, "www.apple.com"), Some(Action::Deny));
    }

    #[test]
    fn deny_wins_when_equally_specific() {
        for config in [
            [("deny", "a*.com"), ("defer", "*e.com")],
            [("defer", "*e.com"), ("deny", "a*.com")],
        ] {
            let patterns = patterns(&config);
            assert_eq!(action(&patterns, "apple.com"), Some(Action::Deny));
        }
    }

    #[test]
    fn specificity_ranks_labels_from_the_top_level() {
        assert_eq!(specificity("*.ap?le.**"), vec![(0, 0), (3, 4), (2, 0)]);
        assert_eq!(specificity("[abc]x.com"), vec![(4, 3), (3, 1)]);
    }

    #[test]
    fn denies_with_access_denied_by_default() {
        let patterns = patterns(&[("deny", "*.com")]);
        assert_eq!(
            decision(&patterns, "apple.com"),
            denied(SocketsErrorCode::AccessDenied)
        );
        assert_eq!(decision(&patterns, "wikipedia.org"), deferred());
    }

    #[test]
    fn denies_with_configured_reason() {
        for (value, expected) in [
            ("access-denied", SocketsErrorCode::AccessDenied),
            ("invalid-argument", SocketsErrorCode::InvalidArgument),
            ("other", SocketsErrorCode::Other(None)),
            ("", SocketsErrorCode::AccessDenied),
            (
                "custom-reason",
                SocketsErrorCode::Other(Some("custom-reason".to_string())),
            ),
        ] {
            let patterns = patterns(&[("reason", value), ("deny", "*.com")]);
            assert_eq!(
                decision(&patterns, "apple.com"),
                denied(expected),
                "reason={value}"
            );
        }
    }

    #[test]
    fn reason_does_not_change_the_default() {
        let patterns = patterns(&[("reason", "invalid-argument")]);
        assert_eq!(decision(&patterns, "apple.com"), deferred());
    }

    #[test]
    fn default_deny_uses_configured_reason_regardless_of_order() {
        for config in [
            [("reason", "invalid-argument"), ("default", "deny")],
            [("default", "deny"), ("reason", "invalid-argument")],
        ] {
            let patterns = patterns(&config);
            assert_eq!(
                decision(&patterns, "apple.com"),
                denied(SocketsErrorCode::InvalidArgument)
            );
        }
    }

    #[test]
    fn default_defer() {
        let patterns = patterns(&[("default", "defer")]);
        assert_eq!(decision(&patterns, "apple.com"), deferred());
    }

    #[test]
    fn matching_pattern_overrides_default() {
        let patterns = patterns(&[("default", "deny"), ("defer", "*.com")]);
        assert_eq!(decision(&patterns, "apple.com"), deferred());
        assert_eq!(
            decision(&patterns, "wikipedia.org"),
            denied(SocketsErrorCode::AccessDenied)
        );
    }

    #[test]
    fn unknown_default_is_invalid() {
        assert_eq!(
            parse(&[("default", "grant")]).err().unwrap(),
            "KEY=default VALUE=grant ERROR=expected 'deny' or 'defer'"
        );
    }

    #[test]
    fn invalid_glob_is_invalid() {
        let err = parse(&[("deny-1", "*.com"), ("deny-2", "[")])
            .err()
            .unwrap();
        assert!(err.starts_with("KEY=deny-2 VALUE=[ ERROR="), "{err}");
    }
}
