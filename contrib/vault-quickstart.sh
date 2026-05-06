#!/usr/bin/env bash
#
# vault-quickstart.sh - Provision Vault or OpenBao for rustguac connections.
#
# Three modes, pick one:
#
#   (default)  Bootstrap an existing Vault. VAULT_ADDR + VAULT_TOKEN must
#              already work. The script just creates the policy, AppRole,
#              and prints the rustguac config snippet.
#
#   --dev      Spawn `vault server -dev` (in-memory, root token = "root"),
#              then bootstrap it. Loses everything when the dev process
#              dies. Useful for local development and demos.
#
#   --local    Install Vault or OpenBao as a systemd service on this host
#              with file-backed storage and on-disk auto-unseal. The flavor
#              is whichever CLI we found (vault or bao). NOT a hardened
#              production setup - the unseal key sits under /etc/vault.d/
#              or /etc/openbao/ in plaintext, root-readable. If the box is
#              rooted, the secret store is owned. For a real deployment
#              use cloud-KMS auto-unseal:
#                Vault:    https://developer.hashicorp.com/vault/docs/configuration/seal
#                OpenBao:  https://openbao.org/docs/configuration/seal/
#
# Common usage
#
#   # against a Vault you already run elsewhere:
#   export VAULT_ADDR=https://vault.example.com:8200
#   export VAULT_TOKEN=hvs.xxxxxxxx
#   ./vault-quickstart.sh
#
#   # local single-box rustguac install:
#   sudo ./vault-quickstart.sh --local
#
#   # rapid testing:
#   ./vault-quickstart.sh --dev
#
# Options
#
#   --dev                Start `<cli> server -dev` first.
#   --local              Install vault/openbao as a systemd service with auto-unseal.
#   --cli {vault|bao}    CLI binary to use (default: auto-detect, prefers vault).
#   --addr URL           Vault address (overrides $VAULT_ADDR).
#   --token TOKEN        Vault root/admin token (overrides $VAULT_TOKEN).
#   --mount NAME         KV v2 mount path (default: secret).
#   --base-path NAME     Path under the mount for rustguac data (default: rustguac).
#   --policy NAME        rustguac policy name (default: rustguac).
#   --role NAME          rustguac AppRole name (default: rustguac).
#   -h, --help           Show this help.
#
set -euo pipefail

# --- defaults --------------------------------------------------------------

CLI=""
MODE="bootstrap"   # bootstrap | dev | local
MOUNT="secret"
BASE_PATH="rustguac"
POLICY="rustguac"
ROLE="rustguac"
ADDR_OVERRIDE=""
TOKEN_OVERRIDE=""

# Listen address shared by both flavors. Loopback only - front it with a
# reverse proxy if you need remote access.
LOCAL_LISTEN="127.0.0.1:8200"
LOCAL_API_ADDR="http://${LOCAL_LISTEN}"

# Per-flavor paths populated by set_flavor() after CLI detection. Vault and
# OpenBao have different conventions for system user, config dir, data dir,
# and service name; we honour each so an admin reading the box later isn't
# surprised to find Vault data under /var/lib/openbao or vice-versa.
LOCAL_FLAVOR=""
LOCAL_USER=""
LOCAL_GROUP=""
LOCAL_CONFIG_DIR=""
LOCAL_CONFIG_FILE=""
LOCAL_DATA_DIR=""
LOCAL_INIT_BUNDLE=""
LOCAL_UNSEAL_KEY_FILE=""
LOCAL_ROOT_TOKEN_FILE=""
LOCAL_SECURITY_README=""
LOCAL_UNSEAL_HELPER=""
LOCAL_SYSTEMD_UNIT=""
LOCAL_SERVICE_NAME=""
LOCAL_BINARY=""

# --- arg parsing -----------------------------------------------------------

usage() { sed -n '2,/^set -euo/p' "$0" | sed -n 's/^# \{0,1\}//;/^set -euo/q;p'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)        MODE="dev" ;;
        --local)      MODE="local" ;;
        --cli)        CLI="$2"; shift ;;
        --addr)       ADDR_OVERRIDE="$2"; shift ;;
        --token)      TOKEN_OVERRIDE="$2"; shift ;;
        --mount)      MOUNT="$2"; shift ;;
        --base-path)  BASE_PATH="$2"; shift ;;
        --policy)     POLICY="$2"; shift ;;
        --role)       ROLE="$2"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# --- helpers ---------------------------------------------------------------

log()  { echo "[vault-quickstart] $*"; }
die()  { echo "[vault-quickstart] error: $*" >&2; exit 1; }
warn() { echo "[vault-quickstart] WARN: $*" >&2; }

require_root() {
    [[ $EUID -eq 0 ]] || die "must run as root for --local (try: sudo $0 $*)"
}

# Vault status exit codes:
#   0 = initialised + unsealed
#   1 = error reaching vault (or other unrecoverable)
#   2 = sealed (or uninitialised)
vault_status_code() {
    "$CLI" status >/dev/null 2>&1 && echo 0 && return
    local rc=$?
    echo "$rc"
}

# --- CLI detection ---------------------------------------------------------

if [[ -z "$CLI" ]]; then
    if   command -v vault >/dev/null 2>&1; then CLI=vault
    elif command -v bao   >/dev/null 2>&1; then CLI=bao
    else die "no 'vault' or 'bao' binary found in PATH (install one or pass --cli)"
    fi
fi
LOCAL_BINARY=$(command -v "$CLI") || die "could not resolve $CLI in PATH"
log "using CLI: $CLI ($LOCAL_BINARY)"

# Pick filesystem layout, system user, and service name based on which CLI
# we're driving. Both upstreams ship distinct .deb/.rpm packaging that uses
# the conventions encoded here, so a re-run of this script lines up with
# what the package would have created.
set_flavor() {
    case "$CLI" in
        vault)
            LOCAL_FLAVOR="vault"
            LOCAL_USER="vault"
            LOCAL_GROUP="vault"
            LOCAL_CONFIG_DIR="/etc/vault.d"
            LOCAL_CONFIG_FILE="${LOCAL_CONFIG_DIR}/vault.hcl"
            LOCAL_DATA_DIR="/var/lib/vault/data"
            LOCAL_SYSTEMD_UNIT="/etc/systemd/system/vault.service"
            LOCAL_SERVICE_NAME="vault.service"
            LOCAL_UNSEAL_HELPER="/usr/local/sbin/rustguac-vault-unseal"
            ;;
        bao)
            LOCAL_FLAVOR="openbao"
            LOCAL_USER="openbao"
            LOCAL_GROUP="openbao"
            LOCAL_CONFIG_DIR="/etc/openbao"
            LOCAL_CONFIG_FILE="${LOCAL_CONFIG_DIR}/openbao.hcl"
            LOCAL_DATA_DIR="/var/lib/openbao/data"
            LOCAL_SYSTEMD_UNIT="/etc/systemd/system/openbao.service"
            LOCAL_SERVICE_NAME="openbao.service"
            LOCAL_UNSEAL_HELPER="/usr/local/sbin/rustguac-openbao-unseal"
            ;;
        *) die "unknown CLI flavor: $CLI" ;;
    esac
    LOCAL_INIT_BUNDLE="${LOCAL_CONFIG_DIR}/init-bundle.json"
    LOCAL_UNSEAL_KEY_FILE="${LOCAL_CONFIG_DIR}/unseal-key"
    LOCAL_ROOT_TOKEN_FILE="${LOCAL_CONFIG_DIR}/root-token"
    LOCAL_SECURITY_README="${LOCAL_CONFIG_DIR}/SECURITY.txt"
}
set_flavor

# --- mode: dev -------------------------------------------------------------

start_dev_vault() {
    local dev_log="/tmp/rustguac-vault-quickstart.log"
    log "starting '$CLI server -dev' (in-memory, root token = root)"
    log "  log: $dev_log"
    "$CLI" server -dev \
        -dev-root-token-id=root \
        -dev-listen-address=127.0.0.1:8200 \
        > "$dev_log" 2>&1 &
    DEV_PID=$!
    log "  pid: $DEV_PID  (stop with: kill $DEV_PID)"

    export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
    export VAULT_TOKEN=${VAULT_TOKEN:-root}
    export BAO_ADDR=${BAO_ADDR:-$VAULT_ADDR}
    export BAO_TOKEN=${BAO_TOKEN:-$VAULT_TOKEN}

    for _ in $(seq 1 30); do
        [[ "$(vault_status_code)" -ne 1 ]] && return 0
        sleep 0.5
    done
    echo "--- last 20 lines of $dev_log ---" >&2
    tail -n 20 "$dev_log" >&2 || true
    die "$CLI failed to become reachable within 15s"
}

# --- mode: local -----------------------------------------------------------
#
# Stand up a vault systemd service backed by file storage on this host, with
# the unseal key written to disk so the service comes up unsealed across
# reboots without a human running `vault operator unseal`.
#
# This is convenience-over-security. The unseal key sits at
# /etc/vault.d/unseal-key (0400 root:root). On a single-host rustguac box
# the threat model is "if root is compromised the box is finished anyway",
# but every operator should know that's the trade and pick something else
# (cloud-KMS auto-unseal, transit seal) for higher-stakes deployments.

install_local_vault() {
    require_root "$@"

    # System user. Existing user is fine - the upstream packages create one
    # with the same name we'd pick, so a hand-installed-then-quickstarted
    # box converges cleanly.
    if ! getent passwd "$LOCAL_USER" >/dev/null; then
        log "creating system user '$LOCAL_USER'"
        useradd --system --home "${LOCAL_DATA_DIR%/data}" --shell /usr/sbin/nologin \
            "$LOCAL_USER"
    fi

    # Directories.
    log "creating $LOCAL_CONFIG_DIR and ${LOCAL_DATA_DIR%/data}"
    install -d -m 0750 -o "$LOCAL_USER" -g "$LOCAL_GROUP" "$LOCAL_CONFIG_DIR"
    install -d -m 0750 -o "$LOCAL_USER" -g "$LOCAL_GROUP" "${LOCAL_DATA_DIR%/data}"
    install -d -m 0700 -o "$LOCAL_USER" -g "$LOCAL_GROUP" "$LOCAL_DATA_DIR"

    # Server config. Listening on loopback only - front with reverse proxy
    # or SSH tunnel for remote access. TLS off because we're loopback-only;
    # if you bind to a real interface, add a `listener.tcp.tls_*` block.
    # Vault and OpenBao share HCL grammar so the same config works for both.
    log "writing $LOCAL_CONFIG_FILE"
    cat > "$LOCAL_CONFIG_FILE" <<EOF
# Generated by rustguac contrib/vault-quickstart.sh - local single-box mode
# (flavor: ${LOCAL_FLAVOR}). Loopback-only, file-backed storage, on-disk
# unseal. NOT a hardened HA setup.

ui            = true
disable_mlock = false
api_addr      = "${LOCAL_API_ADDR}"
cluster_addr  = "${LOCAL_API_ADDR/8200/8201}"

storage "file" {
  path = "${LOCAL_DATA_DIR}"
}

listener "tcp" {
  address     = "${LOCAL_LISTEN}"
  tls_disable = "true"
}
EOF
    chown "$LOCAL_USER:$LOCAL_GROUP" "$LOCAL_CONFIG_FILE"
    chmod 0640 "$LOCAL_CONFIG_FILE"

    # Unseal helper. Idempotent - exits 0 if the server is already unsealed,
    # exits 0 (silently) if there's no key file yet (first boot before
    # init), only fires `${CLI} operator unseal` when sealed AND a key is on
    # disk. We bake in the resolved binary path so a PATH change doesn't
    # break the helper at next reboot.
    log "writing $LOCAL_UNSEAL_HELPER"
    cat > "$LOCAL_UNSEAL_HELPER" <<EOF
#!/usr/bin/env bash
# ${LOCAL_UNSEAL_HELPER##*/} - read the on-disk unseal key and feed it to ${LOCAL_FLAVOR}.
# Invoked by ${LOCAL_SERVICE_NAME} ExecStartPost on every (re)start.
set -euo pipefail

KEY_FILE="${LOCAL_UNSEAL_KEY_FILE}"
export VAULT_ADDR="${LOCAL_API_ADDR}"
export BAO_ADDR="${LOCAL_API_ADDR}"

# Wait for the server to become reachable. Status exit codes: 0 unsealed,
# 1 unreachable, 2 sealed/uninitialised.
for _ in \$(seq 1 60); do
    rc=0
    ${LOCAL_BINARY} status >/dev/null 2>&1 || rc=\$?
    case "\$rc" in
        0) exit 0 ;;
        2) break ;;
        *) sleep 1 ;;
    esac
done

[[ -r "\$KEY_FILE" ]] || {
    # No key file yet - server hasn't been initialised. Leave it sealed;
    # the install script handles first-time init separately.
    exit 0
}

${LOCAL_BINARY} operator unseal "\$(cat "\$KEY_FILE")" >/dev/null
EOF
    chmod 0750 "$LOCAL_UNSEAL_HELPER"
    chown root:root "$LOCAL_UNSEAL_HELPER"

    # systemd unit. Cribbed from Vault's recommended unit with the
    # ExecStartPost added. Only written if no unit already exists, so an
    # upstream package's unit isn't clobbered. If the unit exists we add a
    # drop-in instead.
    local doc_url
    case "$LOCAL_FLAVOR" in
        vault)   doc_url="https://developer.hashicorp.com/vault/docs" ;;
        openbao) doc_url="https://openbao.org/docs/" ;;
    esac
    if [[ ! -e "$LOCAL_SYSTEMD_UNIT" ]] && \
       ! systemctl cat "$LOCAL_SERVICE_NAME" >/dev/null 2>&1; then
        log "writing $LOCAL_SYSTEMD_UNIT"
        cat > "$LOCAL_SYSTEMD_UNIT" <<EOF
[Unit]
Description=${LOCAL_FLAVOR} for rustguac
Documentation=${doc_url}
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=${LOCAL_CONFIG_FILE}

[Service]
User=${LOCAL_USER}
Group=${LOCAL_GROUP}
ProtectSystem=full
ProtectHome=read-only
PrivateDevices=yes
PrivateTmp=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=${LOCAL_BINARY} server -config=${LOCAL_CONFIG_FILE}
ExecReload=/bin/kill --signal HUP \$MAINPID
ExecStartPost=+${LOCAL_UNSEAL_HELPER}
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
    else
        # Existing unit - install a drop-in adding only the ExecStartPost.
        local dropin_dir="/etc/systemd/system/${LOCAL_SERVICE_NAME}.d"
        log "${LOCAL_SERVICE_NAME} already managed elsewhere - adding drop-in $dropin_dir/auto-unseal.conf"
        install -d -m 0755 "$dropin_dir"
        cat > "$dropin_dir/auto-unseal.conf" <<EOF
# Added by rustguac contrib/vault-quickstart.sh.
[Service]
ExecStartPost=+${LOCAL_UNSEAL_HELPER}
EOF
    fi

    systemctl daemon-reload
    systemctl enable "$LOCAL_SERVICE_NAME" >/dev/null
    systemctl restart "$LOCAL_SERVICE_NAME"

    # Wait for the server to reach reachable state (sealed or unsealed).
    for _ in $(seq 1 60); do
        local rc
        rc=$(vault_status_code)
        [[ "$rc" -ne 1 ]] && break
        sleep 1
    done

    export VAULT_ADDR="$LOCAL_API_ADDR"
    export BAO_ADDR="$LOCAL_API_ADDR"

    # First-time init? Detect by absence of the bundle file. We do this
    # explicitly rather than catching errors from `${CLI} status` because
    # the helper above silently noops when there's no key on disk.
    if [[ ! -s "$LOCAL_INIT_BUNDLE" ]]; then
        log "${LOCAL_FLAVOR} has never been initialised - running init now"
        # Single key share is the only sensible config for on-disk unseal.
        # If you wanted a real Shamir setup with operators, you wouldn't
        # be using --local in the first place.
        local bundle_tmp
        bundle_tmp=$(mktemp)
        chmod 600 "$bundle_tmp"
        if ! "$CLI" operator init -key-shares=1 -key-threshold=1 -format=json \
                > "$bundle_tmp"; then
            rm -f "$bundle_tmp"
            die "$CLI operator init failed (see: journalctl -u $LOCAL_SERVICE_NAME)"
        fi
        install -m 0400 -o root -g root "$bundle_tmp" "$LOCAL_INIT_BUNDLE"
        rm -f "$bundle_tmp"

        # Extract unseal key + root token. Use python3 if available
        # (most distros), else fall back to a fragile sed/grep. The
        # bundle JSON shape is stable: keys are unseal_keys_b64[] and
        # root_token.
        local unseal_key root_token
        if command -v python3 >/dev/null 2>&1; then
            unseal_key=$(python3 -c \
                "import json,sys;print(json.load(open('$LOCAL_INIT_BUNDLE'))['unseal_keys_b64'][0])")
            root_token=$(python3 -c \
                "import json,sys;print(json.load(open('$LOCAL_INIT_BUNDLE'))['root_token'])")
        else
            unseal_key=$(grep -A1 'unseal_keys_b64' "$LOCAL_INIT_BUNDLE" \
                | tail -n1 | sed -e 's/^[[:space:]]*"//' -e 's/",*$//')
            root_token=$(grep '"root_token"' "$LOCAL_INIT_BUNDLE" \
                | sed -e 's/.*"root_token"[[:space:]]*:[[:space:]]*"//' -e 's/",*$//')
        fi
        [[ -n "$unseal_key" && -n "$root_token" ]] \
            || die "could not extract unseal_key/root_token from $LOCAL_INIT_BUNDLE"

        printf '%s\n' "$unseal_key" \
            | install -m 0400 -o root -g root /dev/stdin "$LOCAL_UNSEAL_KEY_FILE"
        printf '%s\n' "$root_token" \
            | install -m 0400 -o root -g root /dev/stdin "$LOCAL_ROOT_TOKEN_FILE"
    fi

    # Drop the security README so anyone poking at the box understands
    # the trade-offs we made. This is short on purpose - long warnings
    # don't get read.
    local seal_doc
    case "$LOCAL_FLAVOR" in
        vault)   seal_doc="https://developer.hashicorp.com/vault/docs/configuration/seal" ;;
        openbao) seal_doc="https://openbao.org/docs/configuration/seal/" ;;
    esac
    cat > "$LOCAL_SECURITY_README" <<EOF
WARNING: this ${LOCAL_FLAVOR} was provisioned by
contrib/vault-quickstart.sh --local.

The unseal key lives in:
    ${LOCAL_UNSEAL_KEY_FILE}     (mode 0400, root:root)
The root token lives in:
    ${LOCAL_ROOT_TOKEN_FILE}     (mode 0400, root:root)

Anything that gains read access to those files can decrypt every secret
this ${LOCAL_FLAVOR} holds. On a single-host rustguac install where root
compromise already means total compromise, that's a fair trade. It is NOT
acceptable for a multi-tenant or higher-stakes deployment.

For a real production deployment use cloud KMS auto-unseal, transit seal,
or HSM-backed unseal. See:
    ${seal_doc}

Recovery:
  - Re-unseal manually:  ${CLI} operator unseal "\$(sudo cat ${LOCAL_UNSEAL_KEY_FILE})"
  - Get root token:      sudo cat ${LOCAL_ROOT_TOKEN_FILE}
  - Full init bundle:    sudo cat ${LOCAL_INIT_BUNDLE}
EOF
    chmod 0640 "$LOCAL_SECURITY_README"

    # Explicit unseal here in case the helper hasn't fired yet.
    if [[ "$(vault_status_code)" -eq 2 ]]; then
        log "unsealing $LOCAL_FLAVOR"
        "$CLI" operator unseal "$(cat "$LOCAL_UNSEAL_KEY_FILE")" >/dev/null
    fi

    export VAULT_TOKEN="$(cat "$LOCAL_ROOT_TOKEN_FILE")"
    export BAO_ADDR="$VAULT_ADDR"
    export BAO_TOKEN="$VAULT_TOKEN"

    # Loud warning. The script keeps going so the rustguac config snippet
    # still gets printed at the end, but the user sees this first.
    cat <<EOF >&2

###############################################################################
#  SECURITY WARNING (--local mode, ${LOCAL_FLAVOR})
#
#  The unseal key is stored at
#      ${LOCAL_UNSEAL_KEY_FILE}
#  and the root token at
#      ${LOCAL_ROOT_TOKEN_FILE}
#
#  Both are mode 0400 owned by root. Anyone who gets root on this host
#  owns ${LOCAL_FLAVOR} and every secret in it. Use cloud-KMS auto-unseal for
#  any real production deployment.
###############################################################################

EOF
}

# --- mode dispatch ---------------------------------------------------------

case "$MODE" in
    dev)   start_dev_vault ;;
    local) install_local_vault "$@" ;;
    bootstrap) ;;
esac

# Any --addr/--token flag wins over what the modes set.
[[ -n "$ADDR_OVERRIDE"  ]] && export VAULT_ADDR=$ADDR_OVERRIDE  BAO_ADDR=$ADDR_OVERRIDE
[[ -n "$TOKEN_OVERRIDE" ]] && export VAULT_TOKEN=$TOKEN_OVERRIDE BAO_TOKEN=$TOKEN_OVERRIDE

[[ -n "${VAULT_ADDR:-}"  ]] || die "VAULT_ADDR not set (or pass --addr / use --dev / --local)"
[[ -n "${VAULT_TOKEN:-}" ]] || die "VAULT_TOKEN not set (or pass --token / use --dev / --local)"

# --- provisioning (common to all modes) ------------------------------------

log "verifying connectivity to $VAULT_ADDR"
"$CLI" status >/dev/null 2>&1 || die "cannot reach $VAULT_ADDR"
"$CLI" token lookup >/dev/null 2>&1 || die "VAULT_TOKEN rejected by $VAULT_ADDR"

if "$CLI" secrets list -format=json | grep -qE "\"${MOUNT}/\""; then
    log "kv-v2 mount '$MOUNT/' already enabled - leaving alone"
else
    log "enabling kv-v2 at '$MOUNT/'"
    "$CLI" secrets enable -path="$MOUNT" kv-v2 >/dev/null
fi

log "writing policy '$POLICY'"
"$CLI" policy write "$POLICY" - <<EOF >/dev/null
# rustguac connection entries (KV v2 data)
path "${MOUNT}/data/${BASE_PATH}/*" {
    capabilities = ["create", "read", "update", "delete"]
}
# rustguac folder/entry listing and permanent deletion (KV v2 metadata).
# 'delete' on metadata is required for permanent removal in KV v2.
path "${MOUNT}/metadata/${BASE_PATH}/*" {
    capabilities = ["list", "read", "delete"]
}
EOF

if "$CLI" auth list -format=json | grep -q '"approle/"'; then
    log "approle auth method already enabled"
else
    log "enabling approle auth method"
    "$CLI" auth enable approle >/dev/null
fi

log "creating/updating approle role '$ROLE'"
"$CLI" write "auth/approle/role/$ROLE" \
    token_policies="$POLICY" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 >/dev/null

ROLE_ID=$("$CLI" read -field=role_id "auth/approle/role/$ROLE/role-id")
SECRET_ID=$("$CLI" write -field=secret_id -f "auth/approle/role/$ROLE/secret-id")

# --- summary ---------------------------------------------------------------

cat <<EOF

============================================================
  rustguac vault provisioning complete
============================================================

Add to /opt/rustguac/config.toml (or your dev config):

    [vault]
    addr      = "${VAULT_ADDR}"
    mount     = "${MOUNT}"
    base_path = "${BASE_PATH}"
    role_id   = "${ROLE_ID}"

Add to the rustguac systemd env file (default /opt/rustguac/env)
or export in your shell:

    VAULT_SECRET_ID=${SECRET_ID}

Restart rustguac and look for:
    "Vault: authenticated via AppRole, token TTL=..."
============================================================
EOF

case "$MODE" in
    dev) cat <<EOF
DEV NOTE
  - Vault PID: ${DEV_PID}
  - Address:   ${VAULT_ADDR}
  - Root tok:  root  (also in VAULT_TOKEN)
  - In-memory; data is lost when the process stops.
  - Stop:      kill ${DEV_PID}
============================================================
EOF
        ;;
    local) cat <<EOF
LOCAL NOTE
  - systemctl status ${LOCAL_SERVICE_NAME}   # service health
  - journalctl -u ${LOCAL_SERVICE_NAME} -f   # live logs
  - sudo cat ${LOCAL_ROOT_TOKEN_FILE}   # root token
  - Auto-unseals on reboot via ${LOCAL_UNSEAL_HELPER}
  - Read ${LOCAL_SECURITY_README} before running this anywhere serious.
============================================================
EOF
        ;;
esac
