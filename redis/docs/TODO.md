# grounds-redis: plan

- [ ] Laws, per [LAWS.md](LAWS.md): encode reads back as an array of bulk strings, bulk strings are length-framed, null is not empty, parsing is streaming-safe.
- [ ] Pipelining: send several commands, then read their replies in order. `parse` already hands back the bytes after a reply.
- [ ] Binary arguments: `command` taking bytes, not only Strings.
- [ ] RESP3 via `HELLO 3`: maps, sets, doubles, booleans, big numbers, pushes.
- [ ] AUTH and SELECT on connect; a timeout per reply with `wire_recv_timeout`.
- [ ] Share one bytes type with http/wire: move it to `wire`.
- [ ] Deep arrays in `R.show`, which prints nested arrays as `[...]`.
