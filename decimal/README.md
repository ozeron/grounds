# grounds-decimal

Unsigned integers in base 10 for [Bend 2](https://github.com/bendlang/bend), as digits and as text, with proofs that they read back.

```python
import ../decimal/decimal.bend as D

D.show_u32(4294967295)     # "4294967295"
D.read_u32("007")          # Some{7}
D.read_u32("4294967296")   # None{}: past 2^32 - 1
D.of_u32(120)              # DCon{D0, DCon{D2, DCon{D1, DNil}}}: low digit first
D.to_u32(D.of_u32(120))    # Some{120}
```

`U32.show` and `U32.read` compute through division and multiplication, so a law about them cannot see the digits. Here every digit is a constructor (`D0`…`D9`) and a count is a list of them, least significant first (`Dec`, with `DNil` for 0). `bend PROOF.bend` proves, for every U32 `x` and every `Dec` `d`:

| Law | Says |
|---|---|
| `u32_text_round_trip` | `read_u32(show_u32(x)) == Some{x}` |
| `u32_round_trip` | `to_u32(of_u32(x)) == Some{x}` |
| `of_u32_value` | `value(of_u32(x)) == U32.to_nat(x)` |
| `of_u32_trimmed` | `of_u32` writes no leading zeros |
| `parse_show` | `parse(show(d)) == Some{trim(d)}` |
| `trim_value` | dropping leading zeros keeps the value |
| `inc_value` | `value(inc(d)) == 1 + value(d)` |

- `parse` takes one or more ASCII digits and nothing else; no sign, no spaces. It drops leading zeros, so `"007"` reads as 7.
- `to_u32` gives up as soon as a prefix passes 2^32 − 1, so it never builds a Nat past 2^48 − 1, which aborts the runtime, however many digits it gets.
- `inc` counts up one, which is how a byte count is kept in decimal as it grows.
- `value` gives the count as a Nat, for laws and for counts that stay under 2^48.
- Shares no String, so it keeps a program's Strings free of reference counting.

`moon run decimal:check` runs `test.bend` (which checks `show_u32` against `U32.show` over 20,000 values), the laws, and the cold check.
