#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=
phase=
announce() { python3 ../tools/check_phase.py "$@" >&2; }
check() {
  phase="rtc/$1"
  shift
  announce start "$phase"
  "$@"
  announce end "$phase" 0
  phase=
}
skip() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
sys.path.insert(0, "../tools")
from check_phase import announce
for phase in json.load(open("check_phases.json"))["phases"]:
    if phase["optional"] and phase["name"].startswith(sys.argv[1]):
        announce(["skip", phase["name"], sys.argv[2]])
PY
}
cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [ -n "$phase" ]; then
    announce end "$phase" "$result" || result=125
  fi
  if [ -n "$tmp" ]; then rm -rf "$tmp"; fi
  exit "$result"
}
trap cleanup EXIT
check preflight/check_inputs python3 check_inputs.py
check preflight/check_inputs_test python3 check_inputs_test.py
tmp=$(mktemp -d)

check frontend/test bend test.bend
check frontend/integrity_test bend integrity_test.bend
check frontend/fingerprint_test bend fingerprint_test.bend
check frontend/sign_test bend sign_test.bend
check frontend/sha256_test bend sha256_test.bend
check frontend/ice_test bend ice_test.bend
check frontend/retry_test bend retry_test.bend
check frontend/ice_incoming bend ice_incoming.bend --check-only
check frontend/ice_pairs bend ice_pairs.bend --check-only
check frontend/ice_scheduler bend ice_scheduler.bend --check-only
check frontend/ice_attempts bend ice_attempts.bend --check-only
check frontend/ice_registry bend ice_registry.bend --check-only
check frontend/ice_session bend ice_session.bend --check-only
check frontend/ice_valid bend ice_valid.bend --check-only
check frontend/ice_nomination bend ice_nomination.bend --check-only
check frontend/ice_agent bend ice_agent.bend --check-only
check frontend/ice_consent bend ice_consent.bend --check-only
check frontend/ice_consent_server bend ice_consent_server.bend --check-only
check frontend/ice_transport bend ice_transport.bend --check-only
check frontend/sdp bend sdp.bend --check-only
check frontend/signaling bend signaling.bend --check-only
check frontend/signaling_auth bend signaling_auth.bend --check-only
check frontend/signaling_cookie bend signaling_cookie.bend --check-only
check frontend/signaling_test bend signaling_test.bend
check native/build/signaling_cookie sh ../tools/bend_native.sh examples/signaling_cookie.bend "$tmp/signaling_cookie" > /dev/null
check native/check/signaling_cookie_check python3 examples/signaling_cookie_check.py "$tmp/signaling_cookie"
check native/build/sdp sh ../tools/bend_native.sh examples/sdp.bend "$tmp/sdp" > /dev/null
check native/check/sdp_check python3 examples/sdp_check.py "$tmp/sdp"
sh examples/build_signaling.sh "$tmp/signaling_server" > /dev/null
check native/check/signaling_server_check python3 examples/signaling_server_check.py "$tmp/signaling_server"
check native/check/signaling_cookie_expiry_check python3 examples/signaling_cookie_expiry_check.py "$tmp/signaling_server"
check native/build/auth bend examples/auth.bend -o "$tmp/auth" > /dev/null
check native/check/auth_check python3 examples/auth_check.py "$tmp/auth"
check native/build/ice_build bend examples/ice_build.bend -o "$tmp/ice_build" > /dev/null
check native/check/ice_build_check python3 examples/ice_build_check.py "$tmp/ice_build"
check native/build/ice_exchange bend examples/ice_exchange.bend -o "$tmp/ice_exchange" > /dev/null
check native/check/ice_exchange_check python3 examples/ice_exchange_check.py "$tmp/ice_exchange"
check native/build/retry_schedule bend examples/retry_schedule.bend -o "$tmp/retry_schedule" > /dev/null
check native/check/retry_schedule_check python3 examples/retry_schedule_check.py "$tmp/retry_schedule"
check native/build/ice_retry bend examples/ice_retry.bend -o "$tmp/ice_retry" > /dev/null
check native/check/ice_retry_check python3 examples/ice_retry_check.py "$tmp/ice_retry"
check native/build/ice_model bend examples/ice_model.bend -o "$tmp/ice_model" > /dev/null
check native/check/ice_model_check python3 examples/ice_model_check.py "$tmp/ice_model"
check native/build/ice_pairs bend examples/ice_pairs.bend -o "$tmp/ice_pairs" > /dev/null
check native/check/ice_pairs_check python3 examples/ice_pairs_check.py "$tmp/ice_pairs"
check native/build/ice_scheduler bend examples/ice_scheduler.bend -o "$tmp/ice_scheduler" > /dev/null
check native/check/ice_scheduler_check python3 examples/ice_scheduler_check.py "$tmp/ice_scheduler"
check native/build/ice_session bend examples/ice_session.bend -o "$tmp/ice_session" > /dev/null
check native/check/ice_session_check python3 examples/ice_session_check.py "$tmp/ice_session"
check native/build/ice_valid bend examples/ice_valid.bend -o "$tmp/ice_valid" > /dev/null
check native/check/ice_valid_check python3 examples/ice_valid_check.py "$tmp/ice_valid"
check native/check/ice_nomination_request_check python3 examples/ice_nomination_request_check.py "$tmp/ice_valid"
check native/build/ice_nomination_evidence bend examples/ice_nomination_evidence.bend -o "$tmp/ice_nomination_evidence" > /dev/null
check native/check/ice_nomination_evidence_check python3 examples/ice_nomination_evidence_check.py "$tmp/ice_nomination_evidence"
check native/build/ice_agent bend examples/ice_agent.bend -o "$tmp/ice_agent" > /dev/null
check native/check/ice_agent_check python3 examples/ice_agent_check.py "$tmp/ice_agent"
check native/build/ice_consent bend examples/ice_consent.bend -o "$tmp/ice_consent" > /dev/null
check native/check/ice_consent_check python3 examples/ice_consent_check.py "$tmp/ice_consent"
check native/build/ice_transport bend examples/ice_transport.bend -o "$tmp/ice_transport" > /dev/null
check native/check/ice_transport_check python3 examples/ice_transport_check.py "$tmp/ice_transport"
check native/build/ice_consent_udp bend examples/ice_consent_udp.bend -o "$tmp/ice_consent_udp" > /dev/null
check native/check/ice_consent_udp_check python3 examples/ice_consent_udp_check.py "$tmp/ice_consent_udp"
check native/build/ice_transport_udp bend examples/ice_transport_udp.bend -o "$tmp/ice_transport_udp" > /dev/null
check native/check/ice_transport_udp_check python3 examples/ice_transport_udp_check.py "$tmp/ice_transport_udp"
check native/build/ice_agent_udp bend examples/ice_agent_udp.bend -o "$tmp/ice_agent_udp" > /dev/null
check native/check/ice_agent_udp_check python3 examples/ice_agent_udp_check.py "$tmp/ice_agent_udp"
check native/build/ice_nomination_udp bend examples/ice_nomination_udp.bend -o "$tmp/ice_nomination_udp" > /dev/null
check native/check/ice_nomination_udp_check python3 examples/ice_nomination_udp_check.py "$tmp/ice_nomination_udp"
check native/build/ice_session_udp bend examples/ice_session_udp.bend -o "$tmp/ice_session_udp" > /dev/null
check native/check/ice_session_udp_check python3 examples/ice_session_udp_check.py "$tmp/ice_session_udp"
check native/check/ice_valid_udp_check python3 examples/ice_valid_udp_check.py "$tmp/ice_session_udp"
check native/build/ice_clock bend examples/ice_clock.bend -o "$tmp/ice_clock" > /dev/null
check native/check/ice_clock_check python3 examples/ice_clock_check.py "$tmp/ice_clock"
check native/build/ice_shared bend examples/ice_shared.bend -o "$tmp/ice_shared" > /dev/null
check native/check/ice_shared_check python3 examples/ice_shared_check.py "$tmp/ice_shared"
check native/build/ice_accept bend examples/ice_accept.bend -o "$tmp/ice_accept" > /dev/null
check native/check/ice_accept_check python3 examples/ice_accept_check.py "$tmp/ice_accept"
check native/build/ice_duplex bend examples/ice_duplex.bend -o "$tmp/ice_duplex" > /dev/null
check native/check/ice_duplex_check python3 examples/ice_duplex_check.py "$tmp/ice_duplex"
check native/build/binding bend examples/binding.bend -o "$tmp/binding" > /dev/null
check native/check/binding_check python3 examples/binding_check.py "$tmp/binding"
check native/build/stress bend examples/stress.bend -o "$tmp/stress" > /dev/null
check native/check/stress "$tmp/stress"
check native/build/integrity bend examples/integrity.bend -o "$tmp/integrity" > /dev/null
check native/check/integrity "$tmp/integrity"
check native/build/fingerprint bend examples/fingerprint.bend -o "$tmp/fingerprint" > /dev/null
check native/check/fingerprint "$tmp/fingerprint"
check native/build/sign bend examples/sign.bend -o "$tmp/sign" > /dev/null
check native/check/sign "$tmp/sign"

if command -v bun > /dev/null 2>&1; then
  check bun/build/signaling_cookie bend examples/signaling_cookie.bend -o "$tmp/signaling_cookie.js" > /dev/null
  check bun/check/signaling_cookie_check python3 examples/signaling_cookie_check.py bun "$tmp/signaling_cookie.js"
  check bun/build/sdp bend examples/sdp.bend -o "$tmp/sdp.js" > /dev/null
  check bun/check/sdp_check python3 examples/sdp_check.py bun "$tmp/sdp.js"
  check bun/build/signaling_server bend examples/signaling_server.bend -o "$tmp/signaling_server.js" > /dev/null
  check bun/check/signaling_server_check python3 examples/signaling_server_check.py bun "$tmp/signaling_server.js"
  check bun/check/signaling_cookie_expiry_check python3 examples/signaling_cookie_expiry_check.py bun "$tmp/signaling_server.js"
  chrome=${GROUNDS_CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}
  if [ -x "$chrome" ]; then
    check browser/native_live env GROUNDS_CHROME="$chrome" bun examples/signaling_browser_check.mjs "$tmp/browser-native" "$tmp/signaling_server"
    check browser/native_packets python3 examples/signaling_browser_packets.py "$tmp/browser-native"
    check browser/bun_live env GROUNDS_CHROME="$chrome" bun examples/signaling_browser_check.mjs "$tmp/browser-bun" bun "$tmp/signaling_server.js"
    check browser/bun_packets python3 examples/signaling_browser_packets.py "$tmp/browser-bun"
  else
    echo "SKIP Chrome ICE evaluator: set GROUNDS_CHROME to an installed browser executable"
    skip rtc/browser/ "Chrome unavailable"
  fi
  check bun/build/auth bend examples/auth.bend -o "$tmp/auth.js" > /dev/null
  check bun/check/auth_check python3 examples/auth_check.py bun "$tmp/auth.js"
  check bun/build/ice_build bend examples/ice_build.bend -o "$tmp/ice_build.js" > /dev/null
  check bun/check/ice_build_check python3 examples/ice_build_check.py bun "$tmp/ice_build.js"
  check bun/build/ice_exchange bend examples/ice_exchange.bend -o "$tmp/ice_exchange.js" > /dev/null
  check bun/check/ice_exchange_check python3 examples/ice_exchange_check.py bun "$tmp/ice_exchange.js"
  check bun/build/retry_schedule bend examples/retry_schedule.bend -o "$tmp/retry_schedule.js" > /dev/null
  check bun/check/retry_schedule_check python3 examples/retry_schedule_check.py bun "$tmp/retry_schedule.js"
  check bun/build/ice_retry bend examples/ice_retry.bend -o "$tmp/ice_retry.js" > /dev/null
  check bun/check/ice_retry_check python3 examples/ice_retry_check.py bun "$tmp/ice_retry.js"
  check bun/build/ice_model bend examples/ice_model.bend -o "$tmp/ice_model.js" > /dev/null
  check bun/check/ice_model_check python3 examples/ice_model_check.py bun "$tmp/ice_model.js"
  check bun/build/ice_pairs bend examples/ice_pairs.bend -o "$tmp/ice_pairs.js" > /dev/null
  check bun/check/ice_pairs_check python3 examples/ice_pairs_check.py bun "$tmp/ice_pairs.js"
  check bun/build/ice_scheduler bend examples/ice_scheduler.bend -o "$tmp/ice_scheduler.js" > /dev/null
  check bun/check/ice_scheduler_check python3 examples/ice_scheduler_check.py bun "$tmp/ice_scheduler.js"
  check bun/build/ice_session bend examples/ice_session.bend -o "$tmp/ice_session.js" > /dev/null
  check bun/check/ice_session_check python3 examples/ice_session_check.py bun "$tmp/ice_session.js"
  check bun/build/ice_valid bend examples/ice_valid.bend -o "$tmp/ice_valid.js" > /dev/null
  check bun/check/ice_valid_check python3 examples/ice_valid_check.py bun "$tmp/ice_valid.js"
  check bun/check/ice_nomination_request_check python3 examples/ice_nomination_request_check.py bun "$tmp/ice_valid.js"
  check bun/build/ice_nomination_evidence bend examples/ice_nomination_evidence.bend -o "$tmp/ice_nomination_evidence.js" > /dev/null
  check bun/check/ice_nomination_evidence_check python3 examples/ice_nomination_evidence_check.py bun "$tmp/ice_nomination_evidence.js"
  check bun/build/ice_agent bend examples/ice_agent.bend -o "$tmp/ice_agent.js" > /dev/null
  check bun/check/ice_agent_check python3 examples/ice_agent_check.py bun "$tmp/ice_agent.js"
  check bun/build/ice_consent bend examples/ice_consent.bend -o "$tmp/ice_consent.js" > /dev/null
  check bun/check/ice_consent_check python3 examples/ice_consent_check.py bun "$tmp/ice_consent.js"
  check bun/build/ice_transport bend examples/ice_transport.bend -o "$tmp/ice_transport.js" > /dev/null
  check bun/check/ice_transport_check python3 examples/ice_transport_check.py bun "$tmp/ice_transport.js"
  check bun/build/ice_consent_udp bend examples/ice_consent_udp.bend -o "$tmp/ice_consent_udp.js" > /dev/null
  check bun/check/ice_consent_udp_check python3 examples/ice_consent_udp_check.py bun "$tmp/ice_consent_udp.js"
  check bun/build/ice_transport_udp bend examples/ice_transport_udp.bend -o "$tmp/ice_transport_udp.js" > /dev/null
  check bun/check/ice_transport_udp_check python3 examples/ice_transport_udp_check.py bun "$tmp/ice_transport_udp.js"
  check bun/build/ice_agent_udp bend examples/ice_agent_udp.bend -o "$tmp/ice_agent_udp.js" > /dev/null
  check bun/check/ice_agent_udp_check python3 examples/ice_agent_udp_check.py bun "$tmp/ice_agent_udp.js"
  check bun/build/ice_nomination_udp bend examples/ice_nomination_udp.bend -o "$tmp/ice_nomination_udp.js" > /dev/null
  check bun/check/ice_nomination_udp_check python3 examples/ice_nomination_udp_check.py bun "$tmp/ice_nomination_udp.js"
  check bun/build/ice_session_udp bend examples/ice_session_udp.bend -o "$tmp/ice_session_udp.js" > /dev/null
  check bun/check/ice_session_udp_check python3 examples/ice_session_udp_check.py bun "$tmp/ice_session_udp.js"
  check bun/check/ice_valid_udp_check python3 examples/ice_valid_udp_check.py bun "$tmp/ice_session_udp.js"
  check bun/build/ice_clock bend examples/ice_clock.bend -o "$tmp/ice_clock.js" > /dev/null
  check bun/check/ice_clock_check python3 examples/ice_clock_check.py bun "$tmp/ice_clock.js"
  check bun/build/ice_shared bend examples/ice_shared.bend -o "$tmp/ice_shared.js" > /dev/null
  check bun/check/ice_shared_check python3 examples/ice_shared_check.py bun "$tmp/ice_shared.js"
  check bun/build/ice_accept bend examples/ice_accept.bend -o "$tmp/ice_accept.js" > /dev/null
  check bun/check/ice_accept_check python3 examples/ice_accept_check.py bun "$tmp/ice_accept.js"
  check bun/build/ice_duplex bend examples/ice_duplex.bend -o "$tmp/ice_duplex.js" > /dev/null
  check bun/check/ice_duplex_check python3 examples/ice_duplex_check.py bun "$tmp/ice_duplex.js"
  check bun/build/binding bend examples/binding.bend -o "$tmp/binding.js" > /dev/null
  check bun/check/binding_check python3 examples/binding_check.py bun "$tmp/binding.js"
  check bun/build/stress bend examples/stress.bend -o "$tmp/stress.js" > /dev/null
  check bun/check/stress bun "$tmp/stress.js"
  check bun/build/integrity bend examples/integrity.bend -o "$tmp/integrity.js" > /dev/null
  check bun/check/integrity bun "$tmp/integrity.js"
  check bun/build/fingerprint bend examples/fingerprint.bend -o "$tmp/fingerprint.js" > /dev/null
  check bun/check/fingerprint bun "$tmp/fingerprint.js"
  check bun/build/sign bend examples/sign.bend -o "$tmp/sign.js" > /dev/null
  check bun/check/sign bun "$tmp/sign.js"
else
  echo "RTC JS target: Bun unavailable; skipped"
  skip rtc/ "Bun unavailable"
fi
