import Base
import ./json.bend as J

# each def is a test: it checks only if both sides compute to the same value

def R() -> Type:
  Result<&2, &2, J.Error, J.Json>

def ok(j: J.Json) -> Result<&2, &2, J.Error, J.Json>:
  Done{j}

def err(r: J.Reason, offset: U32, line: U32, col: U32) -> Result<&2, &2, J.Error, J.Json>:
  Fail{J.Error{r, offset, line, col}}

# a number from its text; null if the text is not a number
def n(s: String) -> J.Json:
  J.num_u32.go(J.num(s))

def s(x: String) -> J.Json:
  J.JStr{x}

# whitespace (§2)

def ws_all() -> {J.skip_ws(" \t\n\r x") == "x" : String}:
  {==}

def ws_none() -> {J.skip_ws("x ") == "x " : String}:
  {==}

def ws_padded() -> {J.parse(" \n true \r\t") == ok(J.JBool{True{}}) : R()}:
  {==}

def ws_only() -> {J.parse("  ") == err(J.UnexpectedEnd{}, 2, 1, 3) : R()}:
  {==}

def ws_no_vtab() -> {J.parse("\u{B}1") == err(J.UnexpectedChar{'\u{B}'}, 0, 1, 1) : R()}:
  {==}

def empty() -> {J.parse("") == err(J.UnexpectedEnd{}, 0, 1, 1) : R()}:
  {==}

def trailing() -> {J.parse("1 2") == err(J.TrailingInput{}, 2, 1, 3) : R()}:
  {==}

# literals (§3)

def lit_true() -> {J.parse("true") == ok(J.JBool{True{}}) : R()}:
  {==}

def lit_false() -> {J.parse("false") == ok(J.JBool{False{}}) : R()}:
  {==}

def lit_null() -> {J.parse("null") == ok(J.JNull{}) : R()}:
  {==}

def lit_upper() -> {J.parse("True") == err(J.UnexpectedChar{'T'}, 0, 1, 1) : R()}:
  {==}

def lit_partial() -> {J.parse("tru") == err(J.UnexpectedEnd{}, 3, 1, 4) : R()}:
  {==}

def lit_typo() -> {J.parse("nul1") == err(J.UnexpectedChar{'1'}, 3, 1, 4) : R()}:
  {==}

def lit_glued() -> {J.parse("truex") == err(J.TrailingInput{}, 4, 1, 5) : R()}:
  {==}

# numbers (§6)

def num_int() -> {J.parse("42") == ok(n("42")) : R()}:
  {==}

def num_zero() -> {J.parse("0") == ok(n("0")) : R()}:
  {==}

def num_neg() -> {J.parse("-0") == ok(n("-0")) : R()}:
  {==}

def num_frac() -> {J.parse("3.25") == ok(n("3.25")) : R()}:
  {==}

def num_exp() -> {J.parse("-1.5E+10") == ok(n("-1.5E+10")) : R()}:
  {==}

def num_exp_neg() -> {J.parse("2e-3") == ok(n("2e-3")) : R()}:
  {==}

def num_big() -> {J.parse("123456789012345678901234567890") == ok(n("123456789012345678901234567890")) : R()}:
  {==}

def num_plus() -> {J.parse("+1") == err(J.UnexpectedChar{'+'}, 0, 1, 1) : R()}:
  {==}

def num_lead_zero() -> {J.parse("01") == err(J.TrailingInput{}, 1, 1, 2) : R()}:
  {==}

def num_dot_end() -> {J.parse("1.") == err(J.InvalidNumber{}, 2, 1, 3) : R()}:
  {==}

def num_dot_start() -> {J.parse(".5") == err(J.UnexpectedChar{'.'}, 0, 1, 1) : R()}:
  {==}

def num_exp_empty() -> {J.parse("1e") == err(J.InvalidNumber{}, 2, 1, 3) : R()}:
  {==}

def num_minus_only() -> {J.parse("-") == err(J.InvalidNumber{}, 1, 1, 2) : R()}:
  {==}

def num_nan() -> {J.parse("NaN") == err(J.UnexpectedChar{'N'}, 0, 1, 1) : R()}:
  {==}

# strings (§7)

def str_empty() -> {J.parse("\"\"") == ok(s("")) : R()}:
  {==}

def str_plain() -> {J.parse("\"héllo\"") == ok(s("héllo")) : R()}:
  {==}

def str_escapes() -> {J.parse("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"") == ok(s("\"\\/\u{8}\u{C}\n\r\t")) : R()}:
  {==}

def str_u() -> {J.parse("\"\\u00e9\\u00E9\"") == ok(s("éé")) : R()}:
  {==}

def str_pair() -> {J.parse("\"\\uD834\\uDD1E\"") == ok(s("\u{1D11E}")) : R()}:
  {==}

def str_raw_astral() -> {J.parse("\"😀\"") == ok(s("😀")) : R()}:
  {==}

def str_lone_high() -> {J.parse("\"\\uD834\"") == err(J.LoneSurrogate{}, 7, 1, 8) : R()}:
  {==}

def str_lone_low() -> {J.parse("\"\\uDD1E\"") == err(J.LoneSurrogate{}, 1, 1, 2) : R()}:
  {==}

def str_high_then_char() -> {J.parse("\"\\uD834x\"") == err(J.LoneSurrogate{}, 7, 1, 8) : R()}:
  {==}

def str_bad_hex() -> {J.parse("\"\\u12G4\"") == err(J.InvalidUnicode{}, 1, 1, 2) : R()}:
  {==}

def str_bad_escape() -> {J.parse("\"\\x\"") == err(J.InvalidEscape{}, 1, 1, 2) : R()}:
  {==}

def str_ctrl() -> {J.parse("\"a\nb\"") == err(J.ControlChar{}, 2, 1, 3) : R()}:
  {==}

def str_open() -> {J.parse("\"abc") == err(J.UnexpectedEnd{}, 4, 1, 5) : R()}:
  {==}

# arrays (§5)

def arr_empty() -> {J.parse("[ ]") == ok(J.JArr{[]}) : R()}:
  {==}

def arr_mixed() -> {J.parse("[1, \"a\", null, [true]]") == ok(J.JArr{[n("1"), s("a"), J.JNull{}, J.JArr{[J.JBool{True{}}]}]}) : R()}:
  {==}

def arr_trailing_comma() -> {J.parse("[1,]") == err(J.UnexpectedChar{']'}, 3, 1, 4) : R()}:
  {==}

def arr_missing_comma() -> {J.parse("[1 2]") == err(J.UnexpectedChar{'2'}, 3, 1, 4) : R()}:
  {==}

def arr_leading_comma() -> {J.parse("[,1]") == err(J.UnexpectedChar{','}, 1, 1, 2) : R()}:
  {==}

def arr_open() -> {J.parse("[1") == err(J.UnexpectedEnd{}, 2, 1, 3) : R()}:
  {==}

def arr_mismatch() -> {J.parse("[1}") == err(J.UnexpectedChar{'}'}, 2, 1, 3) : R()}:
  {==}

def arr_deep() -> {J.parse("[[[[]]]]") == ok(J.JArr{[J.JArr{[J.JArr{[J.JArr{[]}]}]}]}) : R()}:
  {==}

# objects (§4)

def obj_empty() -> {J.parse("{ }") == ok(J.JObj{[]}) : R()}:
  {==}

def obj_members() -> {J.parse("{\"a\": 1, \"b\": {\"c\": []}}") == ok(J.JObj{[J.Field{"a", n("1")}, J.Field{"b", J.JObj{[J.Field{"c", J.JArr{[]}}]}}]}) : R()}:
  {==}

def obj_dup_kept() -> {J.parse("{\"a\":1,\"a\":2}") == ok(J.JObj{[J.Field{"a", n("1")}, J.Field{"a", n("2")}]}) : R()}:
  {==}

def obj_trailing_comma() -> {J.parse("{\"a\":1,}") == err(J.UnexpectedChar{'}'}, 7, 1, 8) : R()}:
  {==}

def obj_bare_key() -> {J.parse("{a:1}") == err(J.UnexpectedChar{'a'}, 1, 1, 2) : R()}:
  {==}

def obj_num_key() -> {J.parse("{1:1}") == err(J.UnexpectedChar{'1'}, 1, 1, 2) : R()}:
  {==}

def obj_no_colon() -> {J.parse("{\"a\" 1}") == err(J.UnexpectedChar{'1'}, 5, 1, 6) : R()}:
  {==}

def obj_no_value() -> {J.parse("{\"a\":}") == err(J.UnexpectedChar{'}'}, 5, 1, 6) : R()}:
  {==}

def obj_mismatch() -> {J.parse("{\"a\":1]") == err(J.UnexpectedChar{']'}, 6, 1, 7) : R()}:
  {==}

def err_line_col() -> {J.parse("[\n  1,\n  x\n]") == err(J.UnexpectedChar{'x'}, 9, 3, 3) : R()}:
  {==}

# printing (§10)

def show_compact() -> {J.stringify(J.JObj{[J.Field{"a", J.JArr{[n("1"), J.JNull{}]}}, J.Field{"b", J.JObj{[]}}]}) == "{\"a\":[1,null],\"b\":{}}" : String}:
  {==}

def show_escapes() -> {J.stringify(s("\"\\/\u{8}\u{C}\n\r\t\u{1}\u{1F}é")) == "\"\\\"\\\\/\\b\\f\\n\\r\\t\\u0001\\u001fé\"" : String}:
  {==}

def show_pretty() -> {J.pretty(J.JObj{[J.Field{"a", J.JArr{[n("1"), J.JArr{[]}]}}]}, "  ") == "{\n  \"a\": [\n    1,\n    []\n  ]\n}" : String}:
  {==}

def show_scalar() -> {J.pretty(J.JBool{False{}}, "  ") == "false" : String}:
  {==}

# round trips

def rt_doc() -> {J.parse(J.stringify(J.JArr{[s("a\"\n\u{1}😀"), J.JObj{[J.Field{"k", n("-1.5e3")}]}, J.JNull{}]})) == ok(J.JArr{[s("a\"\n\u{1}😀"), J.JObj{[J.Field{"k", n("-1.5e3")}]}, J.JNull{}]}) : R()}:
  {==}

def rt_pretty() -> {J.parse(J.pretty(J.JObj{[J.Field{"a", J.JArr{[n("1"), J.JObj{[]}]}}]}, "\t")) == ok(J.JObj{[J.Field{"a", J.JArr{[n("1"), J.JObj{[]}]}}]}) : R()}:
  {==}

# building and reading

def num_valid() -> {J.num("-0.5e1") == Some{J.JNum{J.Number{True{}, J.IZero{}, J.FSome{J.D5{}, []}, J.ESome{False{}, J.NoSign{}, J.D1{}, []}}}} : Maybe<&2, J.Json>}:
  {==}

def num_text() -> {J.stringify(n("-12.50E+003")) == "-12.50E+003" : String}:
  {==}

def num_invalid() -> {J.num("01") == None{} : Maybe<&2, J.Json>}:
  {==}

def num_u32() -> {J.num_u32(1234) == n("1234") : J.Json}:
  {==}

def get_last_wins() -> {J.get(J.JObj{[J.Field{"a", n("1")}, J.Field{"b", n("2")}, J.Field{"a", n("3")}]}, "a") == Some{n("3")} : Maybe<&2, J.Json>}:
  {==}

def get_missing() -> {J.get(J.JObj{[J.Field{"a", n("1")}]}, "z") == None{} : Maybe<&2, J.Json>}:
  {==}

def get_not_obj() -> {J.get(J.JNull{}, "a") == None{} : Maybe<&2, J.Json>}:
  {==}

def at_index() -> {J.at(J.JArr{[n("1"), n("2")]}, 1n) == Some{n("2")} : Maybe<&2, J.Json>}:
  {==}

def at_out() -> {J.at(J.JArr{[n("1")]}, 1n) == None{} : Maybe<&2, J.Json>}:
  {==}

def as_u32_ok() -> {J.as_u32(n("42")) == Some{42} : Maybe<&2, U32>}:
  {==}

def as_str_ok() -> {J.as_str(s("x")) == Some{"x"} : Maybe<&2, String>}:
  {==}

def as_bool_no() -> {J.as_bool(J.JNull{}) == None{} : Maybe<&2, Bool>}:
  {==}

def bom_skipped() -> {J.parse("\u{FEFF}[]") == ok(J.JArr{[]}) : R()}:
  {==}

def bom_alone() -> {J.parse("\u{FEFF}") == err(J.UnexpectedEnd{}, 1, 1, 2) : R()}:
  {==}

def msg_char() -> {J.message(J.Error{J.UnexpectedChar{'\n'}, 4, 2, 1}) == "2:1: unexpected \"\\n\"" : String}:
  {==}

# bytes (§8.1)

def bytes_ok() -> {J.parse_bytes([34, 226, 130, 172, 34]) == ok(s("\u{20AC}")) : R()}:
  {==}

def bytes_four() -> {J.parse_bytes([34, 240, 159, 152, 128, 34]) == ok(s("\u{1F600}")) : R()}:
  {==}

def bytes_bad() -> {J.parse_bytes([91, 10, 34, 255, 34, 93]) == err(J.InvalidUtf8{}, 3, 2, 2) : R()}:
  {==}

def bytes_overlong() -> {J.parse_bytes([34, 192, 175, 34]) == err(J.InvalidUtf8{}, 1, 1, 2) : R()}:
  {==}

def bytes_surrogate() -> {J.parse_bytes([34, 237, 160, 128, 34]) == err(J.InvalidUtf8{}, 1, 1, 2) : R()}:
  {==}

def bytes_too_big() -> {J.parse_bytes([34, 244, 144, 128, 128, 34]) == err(J.InvalidUtf8{}, 1, 1, 2) : R()}:
  {==}

def bytes_cut() -> {J.parse_bytes([34, 226, 130]) == err(J.InvalidUtf8{}, 1, 1, 2) : R()}:
  {==}

def bytes_first() -> {J.parse_bytes([93, 255]) == err(J.InvalidUtf8{}, 1, 1, 2) : R()}:
  {==}
