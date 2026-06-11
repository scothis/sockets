# `latch-deny-connect-unless-lookup-address`

Sockets latch that implicitly denies connecting to addresses, unless they were granted for wasi:sockets/ip-name-lookup.

The latch granting the looked up name must be nested under this latch.
