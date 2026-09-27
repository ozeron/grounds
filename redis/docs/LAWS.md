# grounds-redis: laws to prove

The laws `LAWS.bend` should state, taken from the RESP spec in [resp.md](resp.md) (redis/docs, "Redis serialization protocol specification"). Section names below are that file's headings. Redis has no RFC; this spec is the reference.

## Commands: what the client sends

1. **A command reads back as the array it was built from.** For any arguments `args`, `parse(encode(args)) == Parsed{Arr{[Bulk{U.encode(a)} for a in args]}, []}`.
   - Spec: "Sending commands to a Redis server": a client sends "an array consisting of only bulk strings".
   - Why: no argument can end the command early or start another one. It is the injection law for Redis: a key holding `\r\n*1\r\n$8\r\nFLUSHALL\r\n` stays one argument.
   - Needs: the length digits read back (`digits(show(n)) == n`), the same lemma as http/wire's `Content-Length` round trip.
2. **Arguments are binary-safe.** Law 1 holds for any bytes, not only UTF-8 text, once `encode` takes `List<List<U32>>`.
   - Spec: "Bulk strings": "can contain any binary data".

## Replies: what the client reads

3. **Bulk strings are length-framed.** For any bytes `d` and any `rest`, `parse("$" ++ show(len(d)) ++ CRLF ++ d ++ CRLF ++ rest) == Parsed{Bulk{d}, rest}`. A CRLF inside `d` never ends it.
   - Spec: "Bulk strings": `$<length>\r\n<data>\r\n`.
4. **Null bulk is not the empty string.** `parse("$-1\r\n") == Parsed{RNil, []}` and `parse("$0\r\n\r\n") == Parsed{Bulk{[]}, []}`.
   - Spec: "Null bulk strings": "a Redis client should return a nil object … rather than the empty string".
5. **Parsing is streaming-safe.** For a complete reply `r` with encoding `e`:
   - any strict prefix of `e` gives `More`, never a wrong reply;
   - `parse(e ++ rest) == Parsed{r, rest}`, so pipelined replies come apart in order.
   - Spec: "Multiple commands and pipelining".
6. **Reply round trip.** For every reply `r` in RESP2 (simple, error, integer, bulk, null, arrays nested to any depth), `parse(write(r)) == Parsed{r, []}`. This needs a reply writer (`write`), which a test server or a proxy would also use.
   - Spec: "RESP protocol description": "the first byte … always identifies its type".
   - Needs: induction over nested arrays through the parser's explicit stack, like json's round trip.
7. **The terminator is strict.** A bare CR or LF in a simple string, error or length line is `Bad`, never accepted.
   - Spec: "Simple strings never contain carriage return (`\r`) or line feed (`\n`) characters", and CRLF "always separates its parts".

## Order

- Start with 4 and 7: definitional or an easy induction.
- Then 3 and 1, with the digits lemma shared with http/wire.
- Then 5, 6 and 2.

RESP3 (maps, sets, doubles, pushes, `HELLO 3`) comes after its parser, with the same laws for the new types.
