# grounds-redis: plan

- [x] Timeouts on every send and reply; a failed client is closed and not handed back.
- [x] AUTH, ACL users, SELECT, HELLO 3; a pool that replaces failed clients; retries on new connections.
- [x] Pipelining; bytes after a reply kept; binary arguments; RESP3 replies.
- [x] Limits: reply bytes, declared lengths and counts; integers kept as text.
- [x] Laws 1-5 proven (docs/LAWS.md); fault tests, fuzzing, live and load tests.
- [ ] Laws 6 and 7 proven, not only fuzzed.
- [ ] Pub/sub: deliver pushes instead of skipping them.
- [ ] Share one bytes type with http/wire: move it to `wire`.
- [ ] A connect timeout: TCP connect to an address that drops packets waits for the OS (about 75 s).
- [ ] Deep aggregates in `R.show`, which prints them nested as `[...]`.
