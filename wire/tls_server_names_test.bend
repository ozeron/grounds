import Base
import ./tls_server_names.bend as N

# each def is a test: it checks only if both sides compute to the same value
# a.test = [97,46,116,101,115,116]; ECDSA 1027, RSA 2052.
def a() -> List<&2,U32>:
  [97,46,116,101,115,116]

def b() -> List<&2,U32>:
  [98,46,116,101,115,116]

# *.w.test
def wild() -> List<&2,U32>:
  [42,46,119,46,116,101,115,116]

# x.w.test, X.W.TEST, w.test, x.y.w.test, unknown.test
def x_w() -> List<&2,U32>:
  [120,46,119,46,116,101,115,116]

def x_w_upper() -> List<&2,U32>:
  [88,46,87,46,84,69,83,84]

def w() -> List<&2,U32>:
  [119,46,116,101,115,116]

def x_y_w() -> List<&2,U32>:
  [120,46,121,46,119,46,116,101,115,116]

def unknown() -> List<&2,U32>:
  [117,46,116,101,115,116]

def both() -> List<&2,U32>:
  [1027,2052]

# 0: a.test RSA, 1: a.test P-256, 2: b.test P-256, 3: *.w.test P-256, 4: default
def hosts() -> List<&2,N.Entry>:
  [N.Entry{[a()],2052,False{}},N.Entry{[a()],1027,False{}},N.Entry{[b()],1027,False{}},
   N.Entry{[wild()],1027,False{}},N.Entry{[],1027,True{}}]

def exact_prefers_ecdsa() -> {N.select(hosts(),a(),both()) == Some{1n} : Maybe<&2,Nat>}:
  {==}

def exact_rsa_only_client() -> {N.select(hosts(),a(),[2052,2053]) == Some{0n} : Maybe<&2,Nat>}:
  {==}

def exact_no_common_scheme_first_candidate() -> {N.select(hosts(),a(),[2055]) == Some{0n} : Maybe<&2,Nat>}:
  {==}

def exact_other_host() -> {N.select(hosts(),b(),both()) == Some{2n} : Maybe<&2,Nat>}:
  {==}

def wildcard_one_label() -> {N.select(hosts(),x_w(),both()) == Some{3n} : Maybe<&2,Nat>}:
  {==}

def wildcard_case_insensitive() -> {N.select(hosts(),x_w_upper(),both()) == Some{3n} : Maybe<&2,Nat>}:
  {==}

def wildcard_not_bare_suffix() -> {N.select(hosts(),w(),both()) == Some{4n} : Maybe<&2,Nat>}:
  {==}

def wildcard_not_two_labels() -> {N.select(hosts(),x_y_w(),both()) == Some{4n} : Maybe<&2,Nat>}:
  {==}

def unknown_default() -> {N.select(hosts(),unknown(),both()) == Some{4n} : Maybe<&2,Nat>}:
  {==}

def absent_sni_default() -> {N.select(hosts(),[],both()) == Some{4n} : Maybe<&2,Nat>}:
  {==}

def no_default_unknown() -> {N.select([N.Entry{[a()],1027,False{}}],unknown(),both()) == None{} : Maybe<&2,Nat>}:
  {==}

def no_default_absent() -> {N.select([N.Entry{[a()],1027,False{}}],[],both()) == None{} : Maybe<&2,Nat>}:
  {==}

# exact beats a wildcard covering the same name: *.w.test vs x.w.test
def exact_beats_wildcard() -> {N.select([N.Entry{[wild()],1027,False{}},N.Entry{[x_w()],1027,False{}}],x_w(),both()) == Some{1n} : Maybe<&2,Nat>}:
  {==}

def valid_hosts() -> {N.validate(hosts()) == None{} : Maybe<&2,String>}:
  {==}

def rejects_duplicate_same_key() -> {N.validate([N.Entry{[a()],1027,False{}},N.Entry{[[65,46,84,69,83,84]],1027,False{}}]) == Some{"duplicate TLS server name for the same key type"} : Maybe<&2,String>}:
  {==}

def rejects_two_defaults() -> {N.validate([N.Entry{[],1027,True{}},N.Entry{[],2052,True{}}]) == Some{"more than one default TLS credential"} : Maybe<&2,String>}:
  {==}

def rejects_empty() -> {N.validate([]) == Some{"no TLS credentials"} : Maybe<&2,String>}:
  {==}

# *.test (one-label suffix), *x.w.test, IPv4 look-alike, nameless non-default
def rejects_tld_wildcard() -> {N.valid([42,46,116,101,115,116]) == False{} : Bool}:
  {==}

def rejects_partial_wildcard() -> {N.valid([42,120,46,119,46,116,101,115,116]) == False{} : Bool}:
  {==}

def rejects_ip_name() -> {N.valid([49,50,55,46,48,46,48,46,49]) == False{} : Bool}:
  {==}

def accepts_wildcard() -> {N.valid(wild()) == True{} : Bool}:
  {==}

def rejects_nameless_host() -> {N.entries_valid([N.Entry{[],1027,False{}}]) == False{} : Bool}:
  {==}
