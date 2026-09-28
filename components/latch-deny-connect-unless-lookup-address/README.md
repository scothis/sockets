# `latch-deny-connect-unless-lookup-address`

Sockets latch that implicitly denies connecting to addresses, unless they were granted for wasi:sockets/ip-name-lookup.

An address is known once the final decision passed to `observe-decision` allows it to be returned from a lookup. To decide which names may be looked up, aggregate this latch with a latch for ip-name-lookup, like `latch-ip-name-lookup-glob`, using a `latch-n` component.
