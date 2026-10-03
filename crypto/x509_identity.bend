import Base
import ./bytes.bend as B

# Typed DNS/IP matching; no certificate, CN, resolution or trust fallback.
def lower(+byte: U32) -> U32:
  Bool.pick(U32, Bool.and(U32.is_ge(byte, 65), U32.is_le(byte, 90)), U32.add(byte, 32), byte)

def alnum(+byte: U32) -> Bool:
  Bool.or(Bool.and(U32.is_ge(lower(byte), 97), U32.is_le(lower(byte), 122)),
    Bool.and(U32.is_ge(byte, 48), U32.is_le(byte, 57)))

def labels(bytes: List<&2, U32>, +count: U32, +last: U32, valid: Bool) -> Bool:
  match bytes:
    case Nil{}: Bool.and(valid, Bool.and(U32.is_gt(count, 0), Bool.and(U32.is_le(count, 63), alnum(last))))
    case Con{46, rest}:
      labels(rest, 0, 0, Bool.and(valid, Bool.and(U32.is_gt(count, 0), Bool.and(U32.is_le(count, 63), alnum(last)))))
    case Con{+byte, rest}:
      labels(rest, U32.add(count, 1), byte, Bool.and(valid,
        Bool.and(U32.is_le(count, 62), Bool.or(alnum(byte), Bool.and(U32.is_gt(count, 0), U32.is_eq(byte, 45))))))

def domain(+bytes: List<&2, U32>) -> Bool:
  Bool.and(Nat.is_le(B.length(bytes), 253n), labels(bytes, 0, 0, True{}))

def same(a: List<&2, U32>, b: List<&2, U32>, +fold: Bool, equal: Bool) -> Bool:
  match a b:
    case Nil{} Nil{}: equal
    case Con{+x, xs} Con{+y, ys}:
      same(xs, ys, fold, Bool.and(equal, U32.is_eq(Bool.pick(U32, fold, lower(x), x), Bool.pick(U32, fold, lower(y), y))))
    case _ _: False{}

def after_label(bytes: List<&2, U32>) -> List<&2, U32>:
  match bytes:
    case Nil{}: []
    case Con{46, rest}: rest
    case Con{_, rest}: after_label(rest)

def dns.checked(valid: Bool, pattern: List<&2, U32>, reference: List<&2, U32>) -> Bool:
  match valid pattern:
    case True{} Con{42, Con{46, +suffix}}:
      Bool.and(domain(suffix), same(suffix, after_label(reference), True{}, True{}))
    case True{} +pattern:
      Bool.and(domain(pattern), same(pattern, reference, True{}, True{}))
    case _ _: False{}

# ASCII LDH/A-label input without a terminal root dot. Reference construction,
# U-label conversion/IDNA validation and public-suffix policy have their own owners.
def dns(+pattern: List<&2, U32>, +reference: List<&2, U32>) -> Bool:
  dns.checked(Bool.and(domain(reference), Nat.is_le(B.length(pattern), 253n)), pattern, reference)

def ip_length(+bytes: List<&2, U32>) -> Bool:
  Bool.or(Nat.is_eq(B.length(bytes), 4n), Nat.is_eq(B.length(bytes), 16n))

def ip(+presented: List<&2, U32>, +reference: List<&2, U32>) -> Bool:
  Bool.and(Bool.and(ip_length(presented), B.valid(presented)),
    Bool.and(Bool.and(ip_length(reference), B.valid(reference)), same(presented, reference, False{}, True{})))
