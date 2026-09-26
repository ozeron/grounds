# grounds-utf8

Strict UTF-8 decoding for [Bend 2](https://github.com/bendlang/bend), per RFC 3629.

```python
import ../utf8/utf8.bend as U

U.decode([226, 130, 172])   # TOk{"€"}
U.decode([97, 255])         # TBad{1, "a"}: the bad sequence starts at char 1
```

- Rejects overlong forms, surrogates (U+D800–U+DFFF), code points past U+10FFFF and cut-off sequences: everything the runtime's text reader turns into U+FFFD.
- `TBad{at, before}` gives the char offset of the first bad sequence and the chars before it, reversed. `back_line(before, 1)` and `back_col(before, 1)` turn that into a line and column.
- Shares no String, so it keeps a program's Strings free of reference counting.

`moon run utf8:check` runs `test.bend`.
