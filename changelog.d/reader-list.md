kind: SecretReader::list (names only)
---
Adds `SecretReader::list`: every name in the store, sorted, for adapters that list (WebHostAnt C7b). Names only: the call never reads a value; it is bounded by the same timeout, reads the file afresh, and fails with the same classes as `get`. Additive. Test with a negative control (the value is in the store and `get` returns it, but nothing `list` returns holds it); a mutation that appends values to the names fails it. Not published.
