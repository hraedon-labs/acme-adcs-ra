#!/bin/sh
# certbot (acme-python) scenario. acme-python implements no keyChange, so
# rollover is reported SKIP for this client, not silently omitted.
# ENDPOINTS: directory new-nonce-head new-acct acct-post new-order order-post-as-get authz challenge finalize cert revoke-cert
CLIENT=certbot
. /harness/clients/lib.sh
export REQUESTS_CA_BUNDLE=/pki/ca.pem
mkdir -p /w/webroot
CB="certbot --non-interactive --server $DIRECTORY_URL --config-dir /w/cfg --work-dir /w/work --logs-dir /w/logs"

step new-account $CB register --agree-tos -m ops@interop.test --eab-kid="$EAB_KID" --eab-hmac-key="$EAB_HMAC"
step issue $CB certonly --webroot -w /w/webroot -d certbot.interop.test --cert-name t1
step issue-second-order $CB certonly --webroot -w /w/webroot -d certbot2.interop.test --cert-name t2
step update-account-contact $CB update_account -m ops2@interop.test
skip key-change "acme-python has no keyChange"
step revoke $CB revoke --cert-path /w/cfg/live/t1/cert.pem --reason keycompromise --no-delete-after-revoke
# A second revocation is answered 200 by design (H-4 in routes/revocation.py):
# RFC 8555 §7.6 says 400 alreadyRevoked, and the RA deliberately deviates so a
# retried revocation never reads as a failure (open decision WI-047). Asserted
# here so a change in either direction is noticed.
step revoke-again-idempotent $CB revoke --cert-path /w/cfg/live/t1/cert.pem --no-delete-after-revoke
step deactivate-account $CB unregister
# No post-deactivation order step: certbot unregister deletes the local
# account, so a further certonly tries to register afresh and never reaches
# the RA with the old key. acme.sh covers the server-side refusal.
cp /w/logs/letsencrypt.log /out/certbot-transcript.log 2>/dev/null || true
