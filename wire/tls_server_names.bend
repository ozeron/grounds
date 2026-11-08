import Base
import ../crypto/x509_identity.bend as I
import ../crypto/bytes.bend as B

# Server credential selection by TLS SNI (RFC 6066 section 3). Pure, bounded,
# no effects. A pattern is an ASCII DNS name or a single-label leftmost
# wildcard "*.suffix" whose suffix has at least two labels. Matching folds
# ASCII case. "*.example.com" matches "a.example.com", never "example.com"
# or "a.b.example.com". Precedence: exact > wildcard > default. Within the
# winning tier the first P-256 credential (ecdsa_secp256r1_sha256, 1027) is
# preferred when the client offers it, then the first RSA credential
# (rsa_pss_rsae_sha256, 2052), then the first candidate (whose negotiation
# then fails with the usual handshake_failure). No candidate: None.
type Entry is Data:
  Entry{names: List<&2,List<&2,U32>>, scheme: U32, default: Bool}

type Rank is Data:
  Rank{index: Nat, tier: U32, scheme: U32, default: Bool}

def max_credentials() -> Nat:
  64n

def max_names() -> Nat:
  100n

def lower(bytes: List<&2,U32>) -> List<&2,U32>:
  match bytes:
    case Nil{}: []
    case Con{+byte,rest}: Con{I.lower(byte),lower(rest)}

def dotted(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Nil{}: False{}
    case Con{+byte,rest}: Bool.or(U32.is_eq(byte,46),dotted(rest))

def numeric(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Nil{}: True{}
    case Con{+byte,rest}: Bool.and(Bool.or(U32.is_eq(byte,46),Bool.and(U32.is_ge(byte,48),U32.is_le(byte,57))),numeric(rest))

def wildcard(pattern: List<&2,U32>) -> Bool:
  match pattern:
    case Con{42,Con{46,_}}: True{}
    case _: False{}

# A configured name: LDH DNS name (not an all-digit IPv4 look-alike) or *.a.b.
def valid(+pattern: List<&2,U32>) -> Bool:
  match pattern:
    case Con{42,Con{46,+suffix}}:
      Bool.and(Nat.is_le(B.length(pattern),253n),Bool.and(I.domain(suffix),Bool.and(dotted(suffix),Bool.not(numeric(suffix)))))
    case +pattern: Bool.and(I.domain(pattern),Bool.not(numeric(pattern)))

def exact(+pattern: List<&2,U32>, +name: List<&2,U32>) -> Bool:
  Bool.and(Bool.not(wildcard(pattern)),I.same(pattern,name,True{},True{}))

def covers(+pattern: List<&2,U32>, +name: List<&2,U32>) -> Bool:
  match pattern:
    case Con{42,Con{46,+suffix}}: I.same(suffix,I.after_label(name),True{},True{})
    case _: False{}

def level(+pattern: List<&2,U32>, +name: List<&2,U32>) -> U32:
  Bool.pick(U32,exact(pattern,name),2,Bool.pick(U32,covers(pattern,name),1,0))

def tier(names: List<&2,List<&2,U32>>, +name: List<&2,U32>, +best: U32) -> U32:
  match names:
    case Nil{}: best
    case Con{+pattern,rest}:
      +found = level(pattern,name)
      tier(rest,name,Bool.pick(U32,U32.is_gt(found,best),found,best))

def ranks(entries: List<&2,Entry>, +name: List<&2,U32>, +index: Nat) -> List<&2,Rank>:
  match entries:
    case Nil{}: []
    case Con{Entry{names,+scheme,+default},rest}:
      Con{Rank{index,tier(names,name,0),scheme,default},ranks(rest,name,Nat.add(index,1n))}

def top(ranks: List<&2,Rank>, +best: U32) -> U32:
  match ranks:
    case Nil{}: best
    case Con{Rank{_,+tier,_,_},rest}: top(rest,Bool.pick(U32,U32.is_gt(tier,best),tier,best))

def candidate(+target: U32, +tier: U32, +default: Bool) -> Bool:
  Bool.pick(Bool,U32.is_gt(target,0),U32.is_eq(tier,target),default)

def pick(ranks: List<&2,Rank>, +target: U32, +scheme: U32, +any: Bool) -> Maybe<&2,Nat>:
  match ranks:
    case Nil{}: None{}
    case Con{Rank{+index,+tier,+offered,+default},rest}:
      Bool.pick(Maybe<&2,Nat>,Bool.and(candidate(target,tier,default),Bool.or(any,U32.is_eq(offered,scheme))),Some{index},pick(rest,target,scheme,any))

def member(+value: U32, values: List<&2,U32>) -> Bool:
  match values:
    case Nil{}: False{}
    case Con{+other,rest}: Bool.or(U32.is_eq(value,other),member(value,rest))

def otherwise(first: Maybe<&2,Nat>, second: Maybe<&2,Nat>) -> Maybe<&2,Nat>:
  match first:
    case Some{index}: Some{index}
    case None{}: second

def preferred(+ranks: List<&2,Rank>, +target: U32, +sigs: List<&2,U32>) -> Maybe<&2,Nat>:
  otherwise(Bool.pick(Maybe<&2,Nat>,member(1027,sigs),pick(ranks,target,1027,False{}),None{}),
    otherwise(Bool.pick(Maybe<&2,Nat>,member(2052,sigs),pick(ranks,target,2052,False{}),None{}),
      pick(ranks,target,0,True{})))

def chosen(+ranks: List<&2,Rank>, +sigs: List<&2,U32>) -> Maybe<&2,Nat>:
  preferred(ranks,top(ranks,0),sigs)

# sni is the validated ClientHello host_name ([] when absent); sigs is the
# offered signature_algorithms list ([] when absent). Returns an entry index.
def select(+entries: List<&2,Entry>, +sni: List<&2,U32>, +sigs: List<&2,U32>) -> Maybe<&2,Nat>:
  chosen(ranks(entries,Bool.pick(List<&2,U32>,I.domain(sni),lower(sni),[]),0n),sigs)

# Startup validation. None means valid; Some{reason} rejects the whole set.
def names_valid(names: List<&2,List<&2,U32>>) -> Bool:
  match names:
    case Nil{}: True{}
    case Con{+name,rest}: Bool.and(valid(name),names_valid(rest))

def clash(+name: List<&2,U32>, others: List<&2,List<&2,U32>>) -> Bool:
  match others:
    case Nil{}: False{}
    case Con{+other,rest}: Bool.or(I.same(name,other,True{},True{}),clash(name,rest))

def clashes(names: List<&2,List<&2,U32>>, +others: List<&2,List<&2,U32>>) -> Bool:
  match names:
    case Nil{}: False{}
    case Con{+name,rest}: Bool.or(clash(name,others),clashes(rest,others))

def duplicate_one(+names: List<&2,List<&2,U32>>, +scheme: U32, rest: List<&2,Entry>) -> Bool:
  match rest:
    case Nil{}: False{}
    case Con{Entry{+others,+other,_},tail}:
      Bool.or(Bool.and(U32.is_eq(scheme,other),clashes(names,others)),duplicate_one(names,scheme,tail))

def duplicates(entries: List<&2,Entry>) -> Bool:
  match entries:
    case Nil{}: False{}
    case Con{Entry{+names,+scheme,_},+rest}: Bool.or(duplicate_one(names,scheme,rest),duplicates(rest))

def defaults(entries: List<&2,Entry>) -> Nat:
  match entries:
    case Nil{}: 0n
    case Con{Entry{_,_,+default},rest}: Nat.add(Bool.pick(Nat,default,1n,0n),defaults(rest))

def count(entries: List<&2,Entry>) -> Nat:
  match entries:
    case Nil{}: 0n
    case Con{_,rest}: Nat.add(1n,count(rest))

def width(names: List<&2,List<&2,U32>>) -> Nat:
  match names:
    case Nil{}: 0n
    case Con{_,rest}: Nat.add(1n,width(rest))

def entry_valid(+names: List<&2,List<&2,U32>>, +default: Bool) -> Bool:
  Bool.and(Nat.is_le(width(names),max_names()),Bool.and(names_valid(names),Bool.or(default,Nat.is_gt(width(names),0n))))

def entries_valid(entries: List<&2,Entry>) -> Bool:
  match entries:
    case Nil{}: True{}
    case Con{Entry{+names,_,+default},rest}: Bool.and(entry_valid(names,default),entries_valid(rest))

def reason(+problem: Bool, message: String, next: Maybe<&2,String>) -> Maybe<&2,String>:
  match problem:
    case True{}: Some{message}
    case False{}: next

def validate(+entries: List<&2,Entry>) -> Maybe<&2,String>:
  reason(Nat.is_eq(count(entries),0n),"no TLS credentials",
    reason(Nat.is_gt(count(entries),max_credentials()),"more than 64 TLS credentials",
      reason(Nat.is_gt(defaults(entries),1n),"more than one default TLS credential",
        reason(Bool.not(entries_valid(entries)),"invalid TLS server name (DNS or *.a.b, at most 100 per credential, at least one unless default)",
          reason(duplicates(entries),"duplicate TLS server name for the same key type",None{})))))
