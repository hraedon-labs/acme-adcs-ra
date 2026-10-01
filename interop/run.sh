#!/usr/bin/env bash
# Stock-client ACME interop harness (work item 31).
#
# Points maintained third-party ACME clients -- certbot, lego, acme.sh and
# Posh-ACME -- at a LOCAL instance of the RA and drives the full endpoint
# inventory each client supports: newNonce, newAccount (EAB), newOrder, authz
# POST-as-GET, challenge, finalize, order polling, certificate download, account
# update, keyChange, revokeCert and account deactivation. The CA behind the RA
# is a throwaway in-memory signer (interop/ra_harness_entry.py); nothing here can
# reach a real AD CS or lab CA.
#
# The clients reach the RA through interop/nonce_fault_proxy.py, which
# terminates TLS and -- with INJECT_BAD_NONCE_EVERY=N (default 3) -- burns the
# nonce of every Nth POST before forwarding it, so each client's badNonce-retry
# path is exercised on every injecting run (the default, and CI). Set
# INJECT_BAD_NONCE_EVERY=0 for a clean run; the summary reports the count.
#
# Rule (AGENTS.md / item 31): a step where a stock client fails and the in-repo
# hand-rolled client passes is a SERVER finding by default, not a client bug.
#
# Usage:  interop/run.sh [client ...]      # default: certbot lego acmesh posh-acme
# Env:    INTEROP_WORK=<dir>  (default: mktemp -d)   KEEP=1 to leave containers up
#         RA_SRC=<checkout>   RA source tree to test (default: this repository)
# Exit:   0 = every expected step passed; 1 = at least one FAIL; 2 = harness error
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RA_SRC="$(cd "${RA_SRC:-$REPO}" && pwd)"
CLIENTS=("$@")
[ ${#CLIENTS[@]} -eq 0 ] && CLIENTS=(certbot lego acmesh posh-acme)
WORK="${INTEROP_WORK:-$(mktemp -d)}"
INJECT="${INJECT_BAD_NONCE_EVERY:-3}"
RUN_ID="acme-interop-$$"
NET="$RUN_ID"
RA_HOST="acme-ra.interop.test"
DIRECTORY_URL="https://$RA_HOST/directory"

# Client images, pinned by tag AND digest (a re-pushed tag must not change what
# runs). Bump deliberately; a client upgrade that breaks is exactly what this
# harness exists to notice. Posh-ACME itself comes from PSGallery at run time,
# pinned by -RequiredVersion.
CERTBOT_IMAGE="${CERTBOT_IMAGE:-certbot/certbot:v5.8.0@sha256:f70ad0adbb7e117f0fe42a63c553f28ea451edabc0148757b6efcd9735acaa20}"
LEGO_IMAGE="${LEGO_IMAGE:-goacme/lego:v5.5.2@sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd}"
ACMESH_IMAGE="${ACMESH_IMAGE:-neilpang/acme.sh:3.1.6@sha256:ce1a90326f84652c740a75cf80428da92b6f239c55ea2dfffad85b1e59b96092}"
PWSH_IMAGE="${PWSH_IMAGE:-mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-600}"   # seconds per client container
POSH_ACME_VERSION="${POSH_ACME_VERSION:-4.34.0}"

mkdir -p "$WORK"/{pki,out,data}
chmod 0777 "$WORK"/out "$WORK"/data
echo "interop work dir: $WORK"

cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then
        echo "KEEP=1: leaving $RUN_ID containers and network up"
        return
    fi
    docker logs "$RUN_ID-ra" >"$WORK/out/ra.log" 2>&1 || true
    docker logs "$RUN_ID-proxy" >"$WORK/out/proxy.log" 2>&1 || true
    docker ps -aq --filter "name=^$RUN_ID-" | xargs -r docker rm -f >/dev/null
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- PKI for the TLS front (not the fake CA; that lives inside the RA) -------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=acme-ra interop TLS root" -keyout "$WORK/pki/ca.key" -out "$WORK/pki/ca.pem" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$RA_HOST" \
    -keyout "$WORK/pki/tls.key" -out "$WORK/pki/tls.csr" 2>/dev/null
openssl x509 -req -in "$WORK/pki/tls.csr" -CA "$WORK/pki/ca.pem" -CAkey "$WORK/pki/ca.key" \
    -CAcreateserial -days 2 -out "$WORK/pki/tls.pem" \
    -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$RA_HOST") 2>/dev/null
chmod 0644 "$WORK"/pki/*

# --- One EAB credential per client (default quota is one account per kid) ---
declare -A KID HMAC
allow="["
for c in "${CLIENTS[@]}"; do
    KID[$c]="$(openssl rand -hex 16)"
    HMAC[$c]="$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
    allow+="{\"kid\":\"${KID[$c]}\",\"mac_key\":\"${HMAC[$c]}\"},"
done
allow="${allow%,}]"
ra_env=(
    -e ACME_RA_BASE_URL="https://$RA_HOST"
    -e ACME_RA_ALLOW_FAKE_ADCS_BACKENDS=true
    -e ACME_RA_BIND_PORT=8000
    -e ACME_RA_DB_PATH=/data/ra.db
    -e ACME_RA_SIEM_JSONL_PATH=/data/siem.jsonl
    -e ACME_RA_EAB_ALLOWLIST="$allow"
)
for c in "${CLIENTS[@]}"; do
    ra_env+=(-e "ACME_RA_SAN_SCOPES__${KID[$c]}__DNS_PATTERNS=[\"*.interop.test\"]")
done

echo "RA under test: $RA_SRC ($(git -C "$RA_SRC" rev-parse --short HEAD 2>/dev/null || echo unknown))"
docker build -q -t acme-ra-interop:local -f "$REPO/interop/Dockerfile" \
    --build-context harness="$REPO/interop" "$RA_SRC" >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$RUN_ID-ra" --network "$NET" --network-alias ra \
    -v "$WORK/data:/data" "${ra_env[@]}" acme-ra-interop:local >/dev/null
docker run -d --name "$RUN_ID-proxy" --network "$NET" --network-alias "$RA_HOST" \
    -v "$WORK/pki:/pki:ro" acme-ra-interop:local \
    python -u /opt/ra/interop/nonce_fault_proxy.py --listen-port 443 --upstream ra:8000 \
    --cert /pki/tls.pem --key /pki/tls.key --inject-bad-nonce-every "$INJECT" >/dev/null

# Wait for the directory through the proxy, as a client would see it.
for _ in $(seq 1 60); do
    if docker run --rm --network "$NET" -v "$WORK/pki:/pki:ro" acme-ra-interop:local \
        python -c "import ssl,urllib.request as u; u.urlopen('$DIRECTORY_URL', context=ssl.create_default_context(cafile='/pki/ca.pem'), timeout=3)" \
        >/dev/null 2>&1; then
        ready=1; break
    fi
    sleep 1
done
if [ "${ready:-0}" != 1 ]; then
    echo "RA did not come up"; { docker logs "$RUN_ID-ra" 2>&1 | tail -40; } || true; exit 2
fi

run_client() {
    local c="$1" image entry script
    case "$c" in
        certbot)   image="$CERTBOT_IMAGE"; entry=sh;   script=/harness/clients/certbot.sh ;;
        lego)      image="$LEGO_IMAGE";    entry=sh;   script=/harness/clients/lego.sh ;;
        acmesh)    image="$ACMESH_IMAGE";  entry=sh;   script=/harness/clients/acmesh.sh ;;
        posh-acme) image="$PWSH_IMAGE";    entry=pwsh; script=/harness/clients/posh-acme.ps1 ;;
        *) echo "unknown client $c"; return 2 ;;
    esac
    mkdir -p "$WORK/w-$c"; chmod 0777 "$WORK/w-$c"
    local args=()
    [ "$entry" = pwsh ] && args=(-NoProfile -File)
    timeout --kill-after=10 "$CLIENT_TIMEOUT" \
    docker run --rm --name "$RUN_ID-$c" --network "$NET" --entrypoint "$entry" \
        -v "$REPO/interop:/harness:ro" -v "$WORK/pki:/pki:ro" \
        -v "$WORK/w-$c:/w" -v "$WORK/out:/out" \
        -e DIRECTORY_URL="$DIRECTORY_URL" -e EAB_KID="${KID[$c]}" -e EAB_HMAC="${HMAC[$c]}" \
        -e POSH_ACME_VERSION="$POSH_ACME_VERSION" \
        "$image" "${args[@]}" "$script" >"$WORK/out/$c.log" 2>&1 || true
    grep '^RESULT ' "$WORK/out/$c.log" || echo "RESULT $c harness FAIL (no results; see $WORK/out/$c.log)"
}

: >"$WORK/out/results.txt"
for c in "${CLIENTS[@]}"; do
    echo "--- $c"
    run_client "$c" | tee -a "$WORK/out/results.txt"
done

docker logs "$RUN_ID-proxy" >"$WORK/out/proxy.log" 2>&1 || true
injected=$(grep -c '^INJECT ' "$WORK/out/proxy.log" || true)
echo "badNonce injections performed: $injected (every $INJECT POSTs)"
pass=$(grep -c ' PASS$' "$WORK/out/results.txt" || true)
fail=$(grep -c ' FAIL' "$WORK/out/results.txt" || true)
skip=$(grep -c ' SKIP' "$WORK/out/results.txt" || true)
echo "SUMMARY pass=$pass fail=$fail skip=$skip  (transcripts: $WORK/out)"
[ "$fail" -eq 0 ] || exit 1
