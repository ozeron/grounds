import Base
import ./sdp.bend as Sdp
import ./ice_transport.bend as T
import ./ice_agent.bend as Agent
import ./ice_session.bend as Session
import ./ice_valid.bend as V
import ./ice_checklist.bend as Check
import ./ice_candidates.bend as C
import ./ice_binding.bend as Ice
import ./ice_incoming.bend as Incoming
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ../json/json.bend as J
import ../crypto/bytes.bend as B
import ../http/core/text.bend as Text

# One already-authenticated signaling connection owns one ICE transport. The
# adapter supplies its actual bound base and fresh host-generated local secret.
# Offer revisions are connection-local and never identify another connection.
type State is Data:
  Fresh{}
  Active{revision: U32, owner: T.State, local: Incoming.Secret, peer: Sdp.Description}
  Ended{}

type Command is Data:
  Offer{revision: U32, description: Sdp.Description}
  Bad{reason: String}

type Change is Data:
  Accepted{state: State, events: List<&2, T.Notice>}
  Rejected{state: State, reason: String}

def command.sdp(value: Sdp.Decoded, revision: U32) -> Command:
  match value:
    case Sdp.Valid{d}: Offer{revision, d}
    case Sdp.Invalid{reason}: Bad{reason}

def command.revision(value: Result<&2, &2, J.Access, U32>, sdp: String) -> Command:
  match value:
    case Done{r}: command.sdp(Sdp.decode(sdp), r)
    case _: Bad{"invalid offer revision"}

def command.offer(ok: Bool, revision: J.Json, sdp: String) -> Command:
  match ok:
    case True{}: command.revision(J.u32(revision), sdp)
    case False{}: Bad{"expected [offer, revision, SDP]"}

def command.json(value: Result<&2, &2, J.Error, J.Json>) -> Command:
  match value:
    case Done{J.JArr{[J.JStr{kind}, revision, J.JStr{sdp}]}}:
      command.offer(Text.same(kind, "offer", True{}), revision, sdp)
    case _: Bad{"expected [offer, revision, SDP]"}

def command.checked(ok: Bool, bytes: List<&2, U32>) -> Command:
  match ok:
    case True{}: command.json(J.parse_bytes(bytes))
    case False{}: Bad{"signaling message exceeds 32768 bytes"}

def command(+bytes: List<&2, U32>) -> Command:
  command.checked(Nat.is_le(B.length(bytes), 32768n), bytes)

def owner(state: State) -> Maybe<&2, T.State>:
  match state:
    case Active{_, transport, _, _}: Some{transport}
    case _: None{}

def replace(state: State, transport: T.State) -> State:
  match state:
    case Active{rev, _, local, peer}: Active{rev, transport, local, peer}
    case other: other

def alive(transport: T.State) -> Bool:
  match transport:
    case T.State{_, _, _, _, _, _, _, _, closed}: Bool.not(closed)

def streams(base: Stun.IPv4, peer: Sdp.Description) -> List<&2, Check.Stream>:
  match peer:
    case Sdp.Description{_, _, _, _, _, cs, _}:
      +candidate : C.Candidate = C.Candidate{1, 2130706431, "local", C.Host{}, base}
      [Check.Stream{1, [C.Local{candidate, candidate}], cs}]

def bind(state: T.State, secret: Incoming.Secret, peer: Sdp.Description, +now: Nat) -> T.Step:
  match secret peer:
    case Incoming.Secret{uf, _} Sdp.Description{remote, password, _, _, _, _, _}:
      T.bind(state, Ice.Credentials{uf, remote, password}, now)

def rejection(events: List<&2, T.Notice>, found: Bool) -> Bool:
  match events:
    case Nil{}: found
    case Con{T.Rejected{}, tail}: rejection(tail, True{})
    case Con{T.Exhausted{}, tail}: rejection(tail, True{})
    case Con{T.Closed{}, tail}: rejection(tail, True{})
    case Con{_, tail}: rejection(tail, found)

def accept.checked(ok: Bool, state: T.State, events: List<&2, T.Notice>, revision: U32,
                   local: Incoming.Secret, peer: Sdp.Description, old: State) -> Change:
  match ok:
    case True{}: Accepted{Active{revision, state, local, peer}, events}
    case False{}: Rejected{old, "ICE credential admission failed"}

def accept(step: T.Step, revision: U32, local: Incoming.Secret, peer: Sdp.Description, old: State) -> Change:
  match step:
    case T.Step{+state, +events}:
      accept.checked(Bool.and(alive(state), Bool.not(rejection(events, False{}))), state, events, revision, local, peer, old)

def create.owner(value: Maybe<&2, T.State>, +local: Incoming.Secret, +peer: Sdp.Description, +now: Nat) -> Change:
  match value:
    case Some{s}: accept(bind(s, local, peer, now), 0, local, peer, Fresh{})
    case None{}: Rejected{Fresh{}, "ICE owner admission failed"}

def create.agent(value: Maybe<&2, Agent.State>, local: Incoming.Secret, peer: Sdp.Description, now: Nat) -> Change:
  match value:
    case Some{s}: create.owner(T.create(s, T.defaults()), local, peer, now)
    case None{}: Rejected{Fresh{}, "ICE candidate admission failed"}

def create(base: Stun.IPv4, +local: Incoming.Secret, +peer: Sdp.Description, role: Ice.Role, now: Nat) -> Change:
  create.agent(Maybe.bind(&2, V.State, Agent.State,
    V.from_session(Session.create(streams(base, peer), role, local, Auth.Legacy{}, 100, 8, 0), 100),
    v => Agent.create(v, Agent.defaults())), local, peer, now)

def same_peer(first: Sdp.Description, second: Sdp.Description) -> Bool:
  match first second:
    case Sdp.Description{uf, pwd, mid, fp, port, _, _} Sdp.Description{newuf, newpwd, newmid, newfp, newport, _, _}:
      Bool.and(Bool.and(Bool.not(String.eq(uf, newuf)), Bool.not(String.eq(pwd, newpwd))),
        Bool.and(Bool.and(String.eq(mid, newmid), U32.is_eq(port, newport)), String.eq(B.hex(fp), B.hex(newfp))))

def restarted.checked(ok: Bool, state: T.State, events: List<&2, T.Notice>, rev: U32,
                      old: State, +local: Incoming.Secret, +peer: Sdp.Description, +now: Nat) -> Change:
  match ok:
    case True{}: accept(T.join(events, bind(state, local, peer, now)), rev, local, peer, old)
    case False{}: Rejected{old, "credential restart rejected"}

def restarted(step: T.Step, +expected: U32, +old: State, +local: Incoming.Secret, +peer: Sdp.Description, +now: Nat) -> Change:
  match step:
    case T.Step{+state, events}:
      match state:
        case T.State{+agent, _, _, _, _, _, _, _, closed}:
          restarted.checked(Bool.and(Bool.not(closed), U32.is_eq(Agent.generation(agent), expected)),
            state, events, expected, old, local, peer, now)

def apply.checked(ok: Bool, +state: State, base: Stun.IPv4, +local: Incoming.Secret,
                  +peer: Sdp.Description, +revision: U32, +now: Nat) -> Change:
  match ok state:
    case True{} Active{_, transport, _, _}:
      restarted(T.restart(transport, streams(base, peer), local, now), revision, state, local, peer, now)
    case _ s: Rejected{s, "stale revision, partial restart or changed DTLS association"}

def apply(state: State, command: Command, base: Stun.IPv4, local: Incoming.Secret, role: Ice.Role, now: Nat) -> Change:
  match state command:
    case Fresh{} Offer{0, peer}: create(base, local, peer, role, now)
    case Active{+rev, +transport, oldlocal, +previous} Offer{+next, +peer}:
      apply.checked(Bool.and(Bool.and(U32.is_lt(rev, 7), U32.is_eq(next, (rev + 1 : U32))),
        Bool.and(alive(transport), same_peer(previous, peer))), Active{rev, transport, oldlocal, previous}, base, local, peer, next, now)
    case s Bad{reason}: Rejected{s, reason}
    case s _: Rejected{s, "unexpected offer revision or closed session"}

def closed(step: T.Step) -> State:
  match step:
    case T.Step{_, _}: Ended{}

def close(state: State) -> State:
  match state:
    case Active{_, transport, _, _}: closed(T.close(transport))
    case _: Ended{}
