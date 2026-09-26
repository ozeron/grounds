# grounds-io

Whole-file reads for [Bend 2](https://github.com/bendlang/bend).

```python
import ../io/io.bend as Io

r : Io.Read <- Io.read_text(path, Some{1000000})   # Got{text}, or TooBig{size}
bs : List<&2, U32> <- Io.read_bytes(path)          # raw bytes, 0..255
```

- `read_text` checks the size before reading, so a limit costs nothing on a big file. The runtime decodes the text and turns each bad UTF-8 sequence into U+FFFD; use `read_bytes` with `grounds-utf8` to reject bad input instead.
- A path is used once, so no String is shared.

`moon run io:check` type-checks it. Planned: chunked reads and writes, for inputs that do not fit in memory.
