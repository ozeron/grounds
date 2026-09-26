import Base
import ./bjson.bend as J

def R() -> Type:
  Result<&2, &2, J.Error, J.Json>

# whitespace
def ws_all() -> {J.skip_ws(" \t\n\r x") == "x" : String}:
  {==}

def ws_none() -> {J.skip_ws("x ") == "x " : String}:
  {==}

def ws_empty() -> {J.skip_ws("") == "" : String}:
  {==}

def ws_padded() -> {J.parse(" \n true \r\t") == Done{J.JBool{True{}}} : R()}:
  {==}

def ws_only() -> {J.parse("  ") == Fail{J.UnexpectedEnd{}} : R()}:
  {==}

def ws_no_vtab() -> {J.parse("\u{B}true") == Fail{J.UnexpectedChar{'\u{B}'}} : R()}:
  {==}

# literals
def lit_true() -> {J.parse("true") == Done{J.JBool{True{}}} : R()}:
  {==}

def lit_false() -> {J.parse("false") == Done{J.JBool{False{}}} : R()}:
  {==}

def lit_null() -> {J.parse("null") == Done{J.JNull{}} : R()}:
  {==}

def lit_upper() -> {J.parse("True") == Fail{J.UnexpectedChar{'T'}} : R()}:
  {==}

def lit_partial() -> {J.parse("tru") == Fail{J.UnexpectedEnd{}} : R()}:
  {==}

def lit_typo() -> {J.parse("nul1") == Fail{J.UnexpectedChar{'1'}} : R()}:
  {==}

def lit_trailing() -> {J.parse("true false") == Fail{J.TrailingInput{}} : R()}:
  {==}

def lit_glued() -> {J.parse("truex") == Fail{J.TrailingInput{}} : R()}:
  {==}

def empty() -> {J.parse("") == Fail{J.UnexpectedEnd{}} : R()}:
  {==}
