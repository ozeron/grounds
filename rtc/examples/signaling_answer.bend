import Base
import ../signaling.bend as Signal
import ../sdp.bend as Sdp
import ../ice_incoming.bend as Incoming
import ../ice_candidates.bend as C
import ../stun.bend as Stun

# This ICE-only answer intentionally advertises a public placeholder fingerprint.
# No DTLS/data/media acceptance can be inferred from it. The adapter replaces this
# fixture renderer when a real Bend DTLS association is available.
def answer(state: Signal.State, +base: Stun.IPv4) -> String:
  match state:
    case Signal.Active{rev, _, Incoming.Secret{uf, pwd}, Sdp.Description{_, _, +mid, _, _, _, _}}:
      "v=0\r\no=grounds 1 " ++ U32.show((rev + 1 : U32)) ++ " IN IP4 127.0.0.1\r\ns=ICE evaluator\r\nt=0 0\r\n" ++
      "a=group:BUNDLE " ++ mid ++ "\r\nm=application " ++ U32.show(C.port(base)) ++ " UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
      "c=IN IP4 " ++ C.host(base) ++ "\r\na=mid:" ++ mid ++ "\r\na=ice-ufrag:" ++ uf ++ "\r\na=ice-pwd:" ++ pwd ++ "\r\n" ++
      "a=ice-options:ice2\r\na=setup:passive\r\na=fingerprint:sha-256 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11\r\n" ++
      "a=sctp-port:5000\r\na=max-message-size:65536\r\na=candidate:local 1 UDP 2130706431 " ++ C.host(base) ++ " " ++ U32.show(C.port(base)) ++ " typ host\r\na=end-of-candidates\r\n"
    case _: ""
