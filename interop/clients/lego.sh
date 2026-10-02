#!/bin/sh
# lego scenario. The lego CLI exposes no account deactivation (SKIP).
# ENDPOINTS: directory new-nonce-head new-acct new-order authz challenge finalize cert revoke-cert key-change
CLIENT=lego
. /harness/clients/lib.sh
export LEGO_CA_CERTIFICATES=/pki/ca.pem
mkdir -p /w/webroot
L="/lego --log.level debug"
COMMON="--server $DIRECTORY_URL --path /w/lego --email ops@interop.test"

step new-account $L accounts register $COMMON --accept-tos --eab --eab.kid="$EAB_KID" --eab.hmac="$EAB_HMAC"
step issue $L run $COMMON --accept-tos --http --http.webroot /w/webroot -d lego.interop.test
# keyrollover asks for confirmation on the console.
step key-change sh -c "echo Y | $L accounts keyrollover $COMMON"
step issue-after-key-change $L run $COMMON --accept-tos --http --http.webroot /w/webroot -d lego2.interop.test
step revoke $L certificates revoke $COMMON --cert.name lego.interop.test --reason 1 --keep
skip deactivate-account "lego CLI exposes no account deactivation"
