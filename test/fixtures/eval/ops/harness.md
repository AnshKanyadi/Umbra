# The convergence harness

Nineteen schedule shapes over a thousand seeds, under AddressSanitizer and
UndefinedBehaviorSanitizer, nightly.

## Restart from log

A replica is torn down mid-run and rebuilt from its own durable logs, then keeps
working. That is the path a real client takes on every start, and a clock that
does not advance for tree operations makes the rebuilt replica reissue counters
it has already used.
