#!/bin/sh
# ENDPOINTS: directory new-nonce-head new-acct acct-post new-order authz challenge finalize cert revoke-cert key-change
# (no order-post-as-get: this RA's finalize returns the order already valid,
#  so acme.sh never polls it)
CLIENT=acme.sh
. /harness/clients/lib.sh
mkdir -p /w/webroot
# acme.sh's default CSR asks for serverAuth,clientAuth; the RA refuses any CSR
# EKU other than exactly serverAuth BY DESIGN (csr_validation.py), so an
# operator must pass --extended-key-usage serverAuth. That is policy, not a
# conformance gap, and the harness says so rather than hiding it.
A="acme.sh --home /w/acmesh --server $DIRECTORY_URL --ca-bundle /pki/ca.pem --debug 2"

step new-account $A --register-account -m ops@interop.test --eab-kid "$EAB_KID" --eab-hmac-key "$EAB_HMAC"
step issue $A --issue -d acmesh.interop.test -w /w/webroot --extended-key-usage serverAuth
step update-account-contact $A --update-account -m ops2@interop.test
step key-change $A --update-account-key
step issue-after-key-change $A --issue -d acmesh2.interop.test -w /w/webroot --extended-key-usage serverAuth
step revoke $A --revoke -d acmesh.interop.test --revoke-reason 1
step deactivate-account $A --deactivate-account
refused order-after-deactivate-refused "account is deactivated" $A --issue -d acmesh3.interop.test -w /w/webroot --extended-key-usage serverAuth --force
