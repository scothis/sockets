# `latch-ip-name-lookup-glob`

Socket latch that uses glob patterns to grant or deny ip-name lookups.

The patterns are defined in a wasi:config/store. Keys starting with `deny` are parsed as globs with matching host names being denied. Multiple patterns are allowed by defining unique config keys (e.g. `deny-1`, `deny-2`, etc). Keys starting with `abstain` are parsed as globs with matching host names abstaining from the decision.

Each label within the hostname is treated like a directory for wildcards. A single `*` matches within the label boundary `.`, while `**` will span labels.

```
*.com

apple.com -> MATCHES
www.apple.com -> NO MATCH
wikipedia.org -> NO MATCH
```

```
**.com

apple.com -> MATCHES
www.apple.com -> MATCHES
wikipedia.org -> NO MATCH
```

When several patterns match a host name, the most specific pattern decides, regardless of whether it is a `deny` or `abstain` pattern or the order the keys are defined in. Patterns are compared label by label starting from the top level label (`com` in `www.apple.com`), the first label that differs decides. Within a label, a literal (`apple`) is more specific than a partial wildcard (`app*`), which is more specific than `*`, which is more specific than `**`. Between two partial wildcards, the one with more literal characters is more specific. When the matching patterns are equally specific, `deny` wins.

```
deny-1=**.com
abstain-1=**.apple.com
deny-2=secret.apple.com

example.com -> DENIED (deny-1)
www.apple.com -> ABSTAINED (abstain-1)
secret.apple.com -> DENIED (deny-2)
```

Host names that do not match any pattern use the `default` decision, either `abstain` (the default) or `deny`.

Denied lookups fail with `access-denied` unless the `reason` key is set. Supported values are `access-denied`, `invalid-argument` and `other`, any other value is reported as `other` with the value as the message. The reason applies to both matching `deny` patterns and a `deny` default, and does not change the default decision.

```
default=deny
reason=invalid-argument
abstain=**.apple.com

www.apple.com -> ABSTAINED
wikipedia.org -> DENIED (invalid-argument)
```

If the config is invalid (a pattern that does not parse as a glob, or an unknown `default` value), the cause is logged when the config is loaded and every lookup fails with an `invalid-config` latch error.

DNS search paths are not known to the gate/latch. The raw DNS name passed from the caller is evaluated. Using fully qualified DNS names will avoid any ambiguity.
