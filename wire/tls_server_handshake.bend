import Base
import ./tls_handshake_codec.bend as C
import ./tls_extensions.bend as E
import ./tls_hello.bend as H
import ./tls_client.bend as Client
import ./bend_tls_client.bend as Transport
import ../crypto/bytes.bend as B
import ../crypto/x509_chain.bend as A

# Certificate/ECDHE negotiation only. Unknown offers remain opaque; supported
# fields have exact vector grammar. No PSK, 0-RTT, tickets or client auth.
type Policy is Data:
  Policy{suites: List<&2,U32>, groups: List<&2,U32>, alpn: Bool}

type Share is Data:
  Share{group: U32, bytes: List<&2,U32>}

type Choice is Data:
  Choice{suite: U32, group: U32, share: List<&2,U32>, sni: List<&2,U32>, alpn: Bool}

def choose(+preferred: List<&2,U32>, +offered: List<&2,U32>) -> U32:
  match preferred:
    case Nil{}: 0
    case Con{+value,rest}: Bool.pick(U32,C.member(value,offered),value,choose(rest,offered))

def vector16(+bytes: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match bytes:
    case Con{a,Con{b,+body}}: Bool.pick(Maybe<&2,List<&2,U32>>,Nat.is_eq(U32.to_nat(E.number(a,b)),B.length(body)),Some{body},None{})
    case _: None{}

def numbers_body(value: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match value:
    case Some{Con{a,Con{b,rest}}}: H.suites(Con{a,Con{b,rest}},[])
    case _: None{}

def numbers(value: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match value:
    case Some{bytes}: numbers_body(vector16(bytes))
    case _: None{}

def versions_numbers(+size: U32, +body: List<&2,U32>, value: Maybe<&2,List<&2,U32>>) -> Maybe<&2,U32>:
  match value:
    case Some{+values}:
      Bool.pick(Maybe<&2,U32>,Bool.and(U32.is_ge(size,2),Nat.is_eq(U32.to_nat(size),B.length(body))),
        Bool.pick(Maybe<&2,U32>,C.member(772,values),None{},Some{70}),Some{50})
    case None{}: Some{50}

def versions(value: Maybe<&2,List<&2,U32>>) -> Maybe<&2,U32>:
  match value:
    case None{}: Some{70}
    case Some{Con{size,+body}}: versions_numbers(size,body,H.suites(body,[]))
    case _: Some{50}

def first(error: Maybe<&2,U32>, next: Maybe<&2,U32>) -> Maybe<&2,U32>:
  match error:
    case Some{code}: Some{code}
    case None{}: next

def valid_field(+valid: Bool, +code: U32) -> Maybe<&2,U32>:
  Bool.pick(Maybe<&2,U32>,valid,None{},Some{code})

def number_field(value: Maybe<&2,List<&2,U32>>) -> Maybe<&2,U32>:
  match value:
    case None{}: Some{50}
    case Some{_}: None{}

def sni_name(value: Maybe<&2,List<&2,U32>>) -> Result<&2,&2,U32,List<&2,U32>>:
  match value:
    case Some{+name}: Bool.pick(Result<&2,&2,U32,List<&2,U32>>,Transport.identity_valid(A.Dns{name}),Done{name},Fail{47})
    case _: Fail{50}

def sni_list(value: Maybe<&2,List<&2,U32>>) -> Result<&2,&2,U32,List<&2,U32>>:
  match value:
    case Some{Con{0,rest}}: sni_name(vector16(rest))
    case _: Fail{50}

def sni(value: Maybe<&2,List<&2,U32>>) -> Result<&2,&2,U32,List<&2,U32>>:
  match value:
    case None{}: Done{[]}
    case Some{bytes}: sni_list(vector16(bytes))

def protocols_part(+found: Bool, +rest: List<&2,U32>, value: Maybe<&2,E.Parts>, next: List<&2,U32> -> Bool -> Result<&2,&2,U32,Bool>) -> Result<&2,&2,U32,Bool>:
  match value:
    case None{}: Fail{50}
    case Some{E.Parts{+name,tail}}: next(tail,Bool.or(found,H.same(name,Client.http11(),True{})))

def protocols_go(fuel: Nat, +bytes: List<&2,U32>, +found: Bool) -> Result<&2,&2,U32,Bool>:
  match fuel bytes:
    case _ Nil{}: Done{found}
    case 0n _: Fail{50}
    case _ Con{0,_}: Fail{50}
    case 1n+p Con{size,rest}: protocols_part(found,[],E.take(U32.to_nat(size),rest,[]),r => f => protocols_go(p,r,f))

def alpn_result(+enabled: Bool, result: Result<&2,&2,U32,Bool>) -> Result<&2,&2,U32,Bool>:
  match result:
    case Fail{code}: Fail{code}
    case Done{found}: Bool.pick(Result<&2,&2,U32,Bool>,Bool.and(enabled,found),Done{True{}},Fail{120})

def alpn_list(+enabled: Bool, value: Maybe<&2,List<&2,U32>>) -> Result<&2,&2,U32,Bool>:
  match value:
    case Some{Nil{}}: Fail{50}
    case Some{+body}: alpn_result(enabled,protocols_go(Nat.add(B.length(body),1n),body,False{}))
    case None{}: Fail{50}

def alpn(+enabled: Bool, value: Maybe<&2,List<&2,U32>>) -> Result<&2,&2,U32,Bool>:
  match value:
    case None{}: Done{False{}}
    case Some{bytes}: alpn_list(enabled,vector16(bytes))

def after_group(+group: U32, groups: List<&2,U32>) -> List<&2,U32>:
  match groups:
    case Nil{}: []
    case Con{other,+rest}: Bool.pick(List<&2,U32>,U32.is_eq(group,other),rest,after_group(group,rest))

def shares_part(+group: U32, +groups: List<&2,U32>, words: Array<U32>, +out: List<&2,Share>, part: Maybe<&2,E.Parts>, next: List<&2,U32> -> List<&2,U32> -> Maybe<&1,Array<U32>> -> List<&2,Share> -> Result<&2,&2,U32,List<&2,Share>>) -> Result<&2,&2,U32,List<&2,Share>>:
  match part:
    case None{}: Fail{50}
    case Some{E.Parts{bytes,rest}}: next(rest,after_group(group,groups),E.mark(group,words),Con{Share{group,bytes},out})

def shares_checked(+valid: Bool, +group: U32, +groups: List<&2,U32>, words: Array<U32>, +out: List<&2,Share>, part: Maybe<&2,E.Parts>, next: List<&2,U32> -> List<&2,U32> -> Maybe<&1,Array<U32>> -> List<&2,Share> -> Result<&2,&2,U32,List<&2,Share>>) -> Result<&2,&2,U32,List<&2,Share>>:
  match valid:
    case False{}: Fail{47}
    case True{}: shares_part(group,groups,words,out,part,next)

def shares_loop(fuel: Nat, +bytes: List<&2,U32>, +groups: List<&2,U32>, words: Maybe<&1,Array<U32>>, +out: List<&2,Share>) -> Result<&2,&2,U32,List<&2,Share>>:
  match fuel bytes words:
    case _ _ None{}: Fail{47}
    case _ Nil{} Some{_}: Done{List.reverse(&2,Share,out)}
    case 0n _ _: Fail{50}
    case 1n+p Con{a,Con{b,Con{c,Con{d,rest}}}} Some{words}:
      +group = E.number(a,b)
      +size = E.number(c,d)
      shares_checked(Bool.and(C.member(group,groups),U32.is_gt(size,0)),group,groups,words,out,E.take(U32.to_nat(size),rest,[]),r => gs => ws => o => shares_loop(p,r,gs,ws,o))
    case _ _ _: Fail{50}

def shares_list(value: Maybe<&2,List<&2,U32>>, +groups: List<&2,U32>) -> Result<&2,&2,U32,List<&2,Share>>:
  match value:
    case None{}: Fail{50}
    case Some{+body}: shares_loop(Nat.add(B.length(body),1n),body,groups,Some{Array.new(U32,11n,0)},[])

def shares(value: Maybe<&2,List<&2,U32>>, +groups: List<&2,U32>) -> Result<&2,&2,U32,List<&2,Share>>:
  match value:
    case None{}: Fail{109}
    case Some{bytes}: shares_list(vector16(bytes),groups)

def share(+group: U32, +values: List<&2,Share>) -> List<&2,U32>:
  match values:
    case Nil{}: []
    case Con{Share{other,bytes},rest}: Bool.pick(List<&2,U32>,U32.is_eq(group,other),bytes,share(group,rest))

# Parse ignored PSK identities/binders for framing/count/order, never verify or
# accept a binder. This server always performs certificate authentication.
def identities_part(value: Maybe<&2,E.Parts>, +count: Nat, next: List<&2,U32> -> Nat -> Maybe<&2,Nat>) -> Maybe<&2,Nat>:
  match value:
    case Some{E.Parts{_,Con{_,Con{_,Con{_,Con{_,rest}}}}}}: next(rest,Nat.add(count,1n))
    case _: None{}

def identities_size(+size: U32, +rest: List<&2,U32>, +count: Nat, next: List<&2,U32> -> Nat -> Maybe<&2,Nat>) -> Maybe<&2,Nat>:
  match size:
    case 0: None{}
    case size: identities_part(E.take(U32.to_nat(size),rest,[]),count,next)

def identities_go(fuel: Nat, +bytes: List<&2,U32>, +count: Nat) -> Maybe<&2,Nat>:
  match fuel bytes:
    case _ Nil{}: Some{count}
    case 0n _: None{}
    case 1n+p Con{a,Con{b,rest}}: identities_size(E.number(a,b),rest,count,r => n => identities_go(p,r,n))
    case _ _: None{}

def binders_part(value: Maybe<&2,E.Parts>, +count: Nat, next: List<&2,U32> -> Nat -> Maybe<&2,Nat>) -> Maybe<&2,Nat>:
  match value:
    case Some{E.Parts{_,rest}}: next(rest,Nat.add(count,1n))
    case _: None{}

def binders_size(+valid: Bool, +size: U32, +rest: List<&2,U32>, +count: Nat, next: List<&2,U32> -> Nat -> Maybe<&2,Nat>) -> Maybe<&2,Nat>:
  match valid:
    case False{}: None{}
    case True{}: binders_part(E.take(U32.to_nat(size),rest,[]),count,next)

def binders_go(fuel: Nat, +bytes: List<&2,U32>, +count: Nat) -> Maybe<&2,Nat>:
  match fuel bytes:
    case _ Nil{}: Some{count}
    case 0n _: None{}
    case 1n+p Con{+size,rest}: binders_size(U32.is_ge(size,32),size,rest,count,r => n => binders_go(p,r,n))

def psk_counts(a: Maybe<&2,Nat>, b: Maybe<&2,Nat>) -> Bool:
  match a b:
    case Some{+a} Some{b}: Bool.and(Nat.is_gt(a,0n),Nat.is_eq(a,b))
    case _ _: False{}

def psk_binders(+ids: List<&2,U32>, value: Maybe<&2,List<&2,U32>>) -> Bool:
  match value:
    case Some{+bind}: psk_counts(identities_go(Nat.add(B.length(ids),1n),ids,0n),binders_go(Nat.add(B.length(bind),1n),bind,0n))
    case _: False{}

def psk_part(value: Maybe<&2,E.Parts>) -> Bool:
  match value:
    case Some{E.Parts{ids,tail}}: psk_binders(ids,vector16(tail))
    case _: False{}

def psk(+bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Con{a,Con{b,rest}}: psk_part(E.take(U32.to_nat(E.number(a,b)),rest,[]))
    case _: False{}

def modes(+bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Con{+size,+body}: Bool.and(U32.is_gt(size,0),Nat.is_eq(U32.to_nat(size),B.length(body)))
    case _: False{}

def zeroes(+bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Nil{}: True{}
    case Con{byte,rest}: Bool.and(U32.is_eq(byte,0),zeroes(rest))

def bodies(+values: List<&2,E.Extension>) -> Maybe<&2,U32>:
  match values:
    case Nil{}: None{}
    case Con{E.Extension{41,+bytes},Nil{}}: valid_field(psk(bytes),50)
    case Con{E.Extension{41,_},_}: Some{47}
    case Con{E.Extension{42,+bytes},rest}: first(valid_field(Nat.is_eq(B.length(bytes),0n),50),bodies(rest))
    case Con{E.Extension{44,+bytes},rest}: first(valid_field(C.cookie_field(bytes),50),bodies(rest))
    case Con{E.Extension{45,+bytes},rest}: first(valid_field(modes(bytes),50),bodies(rest))
    case Con{E.Extension{50,bytes},rest}: first(number_field(numbers(Some{bytes})),bodies(rest))
    case Con{E.Extension{49,+bytes},rest}: first(valid_field(Nat.is_eq(B.length(bytes),0n),50),bodies(rest))
    case Con{E.Extension{21,bytes},rest}: first(valid_field(zeroes(bytes),47),bodies(rest))
    case Con{_,rest}: bodies(rest)

def present(value: Maybe<&2,List<&2,U32>>) -> Bool:
  match value:
    case Some{_}: True{}
    case None{}: False{}

def required(+extensions: List<&2,E.Extension>) -> Maybe<&2,U32>:
  first(versions(Client.find(43,extensions)),first(
    Bool.pick(Maybe<&2,U32>,Bool.and(present(Client.find(10,extensions)),present(Client.find(13,extensions))),None{},Some{109}),
    first(C.validate_extensions(1,[],extensions),first(bodies(extensions),
      valid_field(Bool.or(Bool.not(present(Client.find(41,extensions))),present(Client.find(45,extensions))),109)))))

def selected_names(+suite: U32, +group: U32, +share: List<&2,U32>, name: Result<&2,&2,U32,List<&2,U32>>, protocol: Result<&2,&2,U32,Bool>) -> Result<&2,&2,U32,Choice>:
  match name protocol:
    case Fail{code} _: Fail{code}
    case _ Fail{code}: Fail{code}
    case Done{sni} Done{alpn}: Done{Choice{suite,group,share,sni,alpn}}

def selected_share(+suite: U32, +group: U32, +extensions: List<&2,E.Extension>, +alpn_enabled: Bool, shares: Result<&2,&2,U32,List<&2,Share>>) -> Result<&2,&2,U32,Choice>:
  match shares:
    case Fail{code}: Fail{code}
    case Done{values}: selected_names(suite,group,share(group,values),sni(Client.find(0,extensions)),alpn(alpn_enabled,Client.find(16,extensions)))

def selected(+valid: Bool, +suite: U32, +group: U32, +extensions: List<&2,E.Extension>, +alpn: Bool, +groups: List<&2,U32>) -> Result<&2,&2,U32,Choice>:
  match valid:
    case False{}: Fail{40}
    case True{}: selected_share(suite,group,extensions,alpn,shares(Client.find(51,extensions),groups))

def algorithms(policy: Policy, +scheme: U32, +offered: List<&2,U32>, +extensions: List<&2,E.Extension>, groups: Maybe<&2,List<&2,U32>>, signatures: Maybe<&2,List<&2,U32>>) -> Result<&2,&2,U32,Choice>:
  match policy groups signatures:
    case Policy{preferred_suites,preferred_groups,alpn} Some{+groups} Some{+signatures}:
      +suite = choose(preferred_suites,offered)
      +group = choose(preferred_groups,groups)
      selected(Bool.and(U32.is_gt(suite,0),Bool.and(U32.is_gt(group,0),C.member(scheme,signatures))),suite,group,extensions,alpn,groups)
    case _ _ _: Fail{50}

def negotiate_required(policy: Policy, +scheme: U32, +offered: List<&2,U32>, +extensions: List<&2,E.Extension>, error: Maybe<&2,U32>) -> Result<&2,&2,U32,Choice>:
  match error:
    case Some{code}: Fail{code}
    case None{}: algorithms(policy,scheme,offered,extensions,numbers(Client.find(10,extensions)),numbers(Client.find(13,extensions)))

def negotiate_hello(policy: Policy, +scheme: U32, hello: H.Hello) -> Result<&2,&2,U32,Choice>:
  match hello:
    case H.Client{_,_,offered,+extensions}: negotiate_required(policy,scheme,offered,extensions,required(extensions))
    case _: Fail{10}

def legacy_extensions(value: Maybe<&2,List<&2,E.Extension>>) -> Bool:
  match value:
    case Some{extensions}: Bool.not(present(Client.find(43,extensions)))
    case None{}: False{}

def legacy_compression(value: Maybe<&2,E.Parts>) -> Bool:
  match value:
    case Some{E.Parts{_,[1,0]}}: True{}
    case Some{E.Parts{_,Con{1,Con{0,extensions}}}}: legacy_extensions(E.parse(extensions))
    case _: False{}

def legacy_suites(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Con{a,Con{b,rest}}:
      +size=U32.to_nat(E.number(a,b))
      Bool.and(Bool.and(Nat.is_ge(size,2n),Nat.is_eq(Nat.mod(size,2n),0n)),legacy_compression(E.take(size,rest,[])))
    case _: False{}

def legacy_session_part(value: Maybe<&2,E.Parts>) -> Bool:
  match value:
    case Some{E.Parts{_,rest}}: legacy_suites(rest)
    case _: False{}

def legacy_random(value: Maybe<&2,E.Parts>) -> Bool:
  match value:
    case Some{E.Parts{_,Con{+size,rest}}}: Bool.and(U32.is_le(size,32),legacy_session_part(E.take(U32.to_nat(size),rest,[])))
    case _: False{}

def legacy(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Con{1,Con{a,Con{b,Con{c,Con{3,Con{3,+body}}}}}}:
      Bool.and(Nat.is_eq(C.length24(a,b,c),Nat.add(2n,B.length(body))),legacy_random(E.take(32n,body,[])))
    case _: False{}

def negotiate_parsed(policy: Policy, +scheme: U32, bytes: List<&2,U32>, value: Result<&2,&2,U32,C.Message>) -> Result<&2,&2,U32,Choice>:
  match value:
    case Fail{50}: Fail{Bool.pick(U32,legacy(bytes),70,50)}
    case Fail{code}: Fail{code}
    case Done{C.ClientHello{hello}}: negotiate_hello(policy,scheme,hello)
    case _: Fail{10}

def negotiate(policy: Policy, +scheme: U32, +message: List<&2,U32>) -> Result<&2,&2,U32,Choice>:
  negotiate_parsed(policy,scheme,message,C.parse(message))

# Stateful HRR: retain CH1, compare invariant encodings and require the exact
# connection-local random cookie. Padding, PSK binders/ages and early_data are
# the only ignored changes. Cookies do not provide stateless server admission.
def invariant_extensions(+values: List<&2,E.Extension>) -> List<&2,U32>:
  match values:
    case Nil{}: []
    case Con{E.Extension{+kind,body},rest}:
      Bool.pick(List<&2,U32>,C.member(kind,[21,41,42,44,51]),invariant_extensions(rest),B.append(C.extension(kind,body),invariant_extensions(rest)))

def retry_ids_part(value: Maybe<&2,E.Parts>, out: List<&2,List<&2,U32>>, next: List<&2,U32> -> List<&2,List<&2,U32>> -> List<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match value:
    case Some{E.Parts{identity,Con{_,Con{_,Con{_,Con{_,rest}}}}}}: next(rest,Con{identity,out})
    case _: []

def retry_ids_loop(fuel: Nat, bytes: List<&2,U32>, out: List<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match fuel bytes:
    case _ Nil{}: List.reverse(&2,List<&2,U32>,out)
    case 1n+p Con{a,Con{b,rest}}: retry_ids_part(E.take(U32.to_nat(E.number(a,b)),rest,[]),out,r => o => retry_ids_loop(p,r,o))
    case _ _: []

def retry_ids_vector(value: Maybe<&2,E.Parts>) -> List<&2,List<&2,U32>>:
  match value:
    case Some{E.Parts{+ids,_}}: retry_ids_loop(Nat.add(B.length(ids),1n),ids,[])
    case _: []

def retry_ids(value: Maybe<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match value:
    case Some{Con{a,Con{b,rest}}}: retry_ids_vector(E.take(U32.to_nat(E.number(a,b)),rest,[]))
    case _: []

def subsequence_selected(equal: Bool, pending: List<&2,List<&2,U32>>, after: List<&2,List<&2,U32>>, next: List<&2,List<&2,U32>> -> Bool) -> Bool:
  match equal:
    case True{}: next(after)
    case False{}: next(pending)

def subsequence(first: List<&2,List<&2,U32>>, second: List<&2,List<&2,U32>>) -> Bool:
  match first second:
    case _ Nil{}: True{}
    case Nil{} _: False{}
    case Con{a,rest} Con{+b,+after}: subsequence_selected(H.same(a,b,True{}),Con{b,after},after,s => subsequence(rest,s))

def retry_share(+value: List<&2,U32>, +cookie: List<&2,U32>, share: Maybe<&2,List<&2,U32>>, +group: U32) -> Bool:
  match share:
    case Some{Con{a,Con{b,Con{c,Con{d,+public}}}}}:
      Bool.and(H.same(value,cookie,True{}),Bool.and(U32.is_eq(E.number(a,b),group),Nat.is_eq(U32.to_nat(E.number(c,d)),B.length(public))))
    case _: False{}

def retry_cookie(value: Maybe<&2,List<&2,U32>>, +cookie: List<&2,U32>, share: Maybe<&2,List<&2,U32>>, +group: U32) -> Bool:
  match value share:
    case Some{value} Some{bytes}: retry_share(value,cookie,vector16(bytes),group)
    case _ _: False{}

def retry_hellos(first: H.Hello, second: H.Hello, +cookie: List<&2,U32>, +group: U32) -> Bool:
  match first second:
    case H.Client{a,b,c,+d} H.Client{e,f,g,+h}:
      Bool.and(H.same(a,e,True{}),Bool.and(H.same(b,f,True{}),Bool.and(H.same(c,g,True{}),
        Bool.and(H.same(invariant_extensions(d),invariant_extensions(h),True{}),
          Bool.and(Bool.not(present(Client.find(42,h))),
            Bool.and(subsequence(retry_ids(Client.find(41,d)),retry_ids(Client.find(41,h))),
              Bool.and(Maybe.is_none(&2,List<&2,U32>,Client.find(44,d)),
                retry_cookie(Client.find(44,h),cookie,Client.find(51,h),group))))))))
    case _ _: False{}

def retry_parsed(first: Result<&2,&2,H.Error,H.Hello>, second: Result<&2,&2,H.Error,H.Hello>, +cookie: List<&2,U32>, +group: U32) -> Bool:
  match first second:
    case Done{first} Done{second}: retry_hellos(first,second,cookie,group)
    case _ _: False{}

def retry_valid(+first: List<&2,U32>, +second: List<&2,U32>, +cookie: List<&2,U32>, +group: U32) -> Bool:
  retry_parsed(H.parse(first),H.parse(second),cookie,group)
