# `latch-ip-name-lookup-glob`

Socket latch that uses glob patterns to grant or deny ip-name lookups.

The patterns are defined in a wasi:config/store. Keys starting with `deny` are parsed as globs with matching host names being denied. Multiple patterns are allowed by defining unique config keys (e.g. `deny-1`, `deny-2`, etc). Keys starting with `grant` are parsed as globs with matching host names being granted.

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

DNS search paths are not known to the gate/latch. The raw DNS name passed from the caller is evaluated. Using fully qualified DNS names will avoid any ambiguity.
