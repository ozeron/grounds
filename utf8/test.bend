import Base
import ./utf8.bend as U

# each def is a test: it checks only if both sides compute to the same value

def T() -> Type:
  U.Text

def ascii() -> {U.decode([104, 105]) == U.TOk{"hi"} : T()}:
  {==}

def euro() -> {U.decode([226, 130, 172]) == U.TOk{"\u{20AC}"} : T()}:
  {==}

def four() -> {U.decode([240, 159, 152, 128]) == U.TOk{"\u{1F600}"} : T()}:
  {==}

def bad_byte() -> {U.decode([97, 255]) == U.TBad{1, "a"} : T()}:
  {==}

def overlong() -> {U.decode([192, 175]) == U.TBad{0, ""} : T()}:
  {==}

def surrogate() -> {U.decode([237, 160, 128]) == U.TBad{0, ""} : T()}:
  {==}

def too_big() -> {U.decode([244, 144, 128, 128]) == U.TBad{0, ""} : T()}:
  {==}

def cut() -> {U.decode([98, 226, 130]) == U.TBad{1, "b"} : T()}:
  {==}

def column() -> {U.back_col("ba\nc", 1) == 3 : U32}:
  {==}

def line() -> {U.back_line("\nb\n", 1) == 3 : U32}:
  {==}

def enc_ascii() -> {U.encode("hi") == [104, 105] : List<&2, U32>}:
  {==}

def enc_two() -> {U.encode("\u{E9}") == [195, 169] : List<&2, U32>}:
  {==}

def enc_euro() -> {U.encode("\u{20AC}") == [226, 130, 172] : List<&2, U32>}:
  {==}

def enc_four() -> {U.encode("\u{1F600}") == [240, 159, 152, 128] : List<&2, U32>}:
  {==}

def enc_back() -> {U.decode(U.encode("a\u{E9}\u{20AC}\u{1F600}")) == U.TOk{"a\u{E9}\u{20AC}\u{1F600}"} : T()}:
  {==}
