import Base
import ./x509_constraints.bend as C

# Bottom-up equivalent of RFC 5280 6.1.4(k)-(n): below counts only
# non-self-issued intermediate CAs, never the target leaf. Each ancestor's
# original arbitrary-size pathLen must cover that count. No narrowing/clamping
# can wrap a large pathLen. Overall certificate depth is bounded separately.
type Decision is Data:
  Allowed{}
  InvalidCa{}
  InvalidUsage{}
  Exceeded{}

def usage.allowed(valid: Bool) -> Decision:
  Bool.pick(Decision, valid, Allowed{}, Exceeded{})

def usage.bits(valid: Bool, limit: Maybe<&1, List<&2, U32>>, below: U32) -> Decision:
  match valid:
    case False{}: InvalidUsage{}
    case True{}: usage.allowed(C.path_allows(limit, below))

def usage(value: Maybe<&1, C.Usage>, limit: Maybe<&1, List<&2, U32>>, below: U32) -> Decision:
  match value:
    case Some{C.Usage{bits}}: usage.bits(U32.is_ne(U32.and(bits, 4), 0), limit, below)
    case None{}: InvalidUsage{}

def basic(value: Maybe<&1, C.Basic>, key_usage: Maybe<&2, List<&2, U32>>, below: U32) -> Decision:
  match value key_usage:
    case Some{C.Basic{True{}, limit}} Some{bytes}: usage(C.usage(bytes), limit, below)
    case Some{C.Basic{True{}, _}} None{}: InvalidUsage{}
    case _ _: InvalidCa{}

# This selected profile requires explicit v3 CA and keyCertSign, including
# certificate-form anchors. There is no out-of-band v1/v2 CA authority input.
def check(version: U32, basic_constraints: Maybe<&2, List<&2, U32>>,
  key_usage: Maybe<&2, List<&2, U32>>, below: U32) -> Decision:
  match version basic_constraints:
    case 2 Some{bytes}: basic(C.basic(bytes), key_usage, below)
    case _ _: InvalidCa{}

def advance(self_issued: Bool, +below: U32) -> U32:
  Bool.pick(U32, self_issued, below, U32.inc(below))
