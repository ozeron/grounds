# Offline public-chain fixtures

Recorded once on 2026-10-24; these files contain public certificates only.
`manifest.json` records each source, PEM/DER SHA-256, issuer, validity,
fixed verification time and independent OpenSSL command/output.

The explicit Mozilla bundle is curl's 2026-10-20 snapshot: 118 roots,
200116 bytes, SHA-256
`796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe`.
The smaller current root count is measured, not an assumed 150–200.
Admission tests additionally cover 200/256 distinct framed anchors using
clearly synthetic self-signature aliases, never claimed as public chains.

The thirteen M5 chains cover Let's Encrypt R10 → ISRG Root X1 and E5/E6 →
ISRG Root X2 (P-384), current Let's Encrypt test hosts, example.com,
Google, letsencrypt.org, GitHub, Cloudflare, Microsoft → DigiCert,
Sectigo/USERTrust and Amazon. Historical chains use 2025-09-01 UTC;
current recordings use 2026-10-24 12:00 UTC. Seven M6 EV chains, recorded
on 2026-11-08 with OpenSSL 4.1 `s_client -showcerts` (SNI, http/1.1) and
fixed at 2026-11-08 12:00 UTC, cover EV subject attributes: www.digicert.com
(DigiCert EV RSA CA G2), www.globalsign.com (street), www.entrust.com
(PrintableString businessCategory), www.db.com (jurisdiction L/ST/C,
postalCode, street), www.postfinance.ch (UTF8String jurisdiction ST and
street), www.apple.com and www.pkobp.pl (UTF8String jurisdiction L/ST).
Each entry lists the leaf's attribute OIDs and string types
(`leaf_subject_attributes`). No offline test uses the wall clock or network. Issued historical certificates were downloaded
from the manifest's crt.sh URLs; CT poison precertificates are excluded.

`crypto/public_chain_check.py` verifies five cases per chain on native:
success, wrong hostname, expiry after the leaf's notAfter, all matching
trust anchors removed, and an unknown signature OID. OpenSSL 3 independently
checks each positive and negative. Unknown signatures must report
`unsupported-algorithm`. Root removal reports `wrong-issuer`, or
`untrusted` when the server also sent the (now unanchored) self-signed root.
Until M6 every removal reported `unsupported-name`: the scan reached the
Mozilla anchors whose subjects carry organizationIdentifier (e-Szigno 2017,
e-Szigno TLS 2023, FNMT) or emailAddress (e-Szigno 2009), which the finite
Name profile could not compare, and EV leaves such as www.digicert.com were
refused outright.

To build the optional native HTTP example, use
`BUN_JSC_useDFGJIT=false BUN_JSC_useFTLJIT=false python3
http/client/public_https_build.py --trace /tmp/public.c /tmp/build.json`
then `tools/bend_native.sh /tmp/public.c /tmp/public-http` under the normal
4096 MiB / 120-second phase guard. The builder disables host TLS/cookie
effects with the established abort overlay; --trace adds only public
negotiation diagnostic prints to a disposable copy of Bend TLS sources.

Run the non-gating internet diagnostic explicitly:

```sh
GROUNDS_PUBLIC_HTTPS_LIVE=1 python3 http/client/public_https_live.py \
  --binary /tmp/public-http \
  --bundle crypto/fixtures/public-chains/mozilla-2026-10-20.pem \
  --report /tmp/public-live.json
```

Without the environment flag it records a skip. Gates force the flag off.
No host cryptography, ambient trust discovery or certificate generation is
part of the Bend path. Python/OpenSSL are offline oracles and recorders only.
