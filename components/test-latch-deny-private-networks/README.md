# `test-latch-deny-private-networks`

Test only, not published.

Composes `latch-cidr-egress` with `latch-deny-private-networks-cidr-config`, to test the config's ranges end to end. The tests also check the ranges directly against addresses that must be denied and addresses that must be deferred.
