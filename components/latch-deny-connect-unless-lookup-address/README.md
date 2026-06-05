# `latch-deny-connect-unless-lookup-address`

Sockets latch that implicitly denies connecting to addresses, unless they were permitted for wasi:sockets/ip-name-lookup.

The latch permitting the looked up name must be nested under this latch.
