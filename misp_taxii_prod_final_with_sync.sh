#!/bin/bash
# misp_taxii_prod_final_with_sync.sh
umask 027
set -euo pipefail

# --- Configuration Variables & Dependencies ---
TAXII_HOST_IP="127.0.0.1"
TAXII_PORT="5000"
INSTALL_DIR="/opt/medallion"
MEDALLION_USER="medallion"
MEDALLION_CONFIG_FILE="$INSTALL_DIR/config.json"
MEDALLION_SERVICE_FILE="/etc/systemd/system/medallion.service"
API_ROOT="api-root-1"

# Known good dependency versions
MEDALLION_VERSION="5.0"
PYMONGO_VERSION="4.6"

# ---------- helpers ----------
get_input() {
  local prompt_message="$1"; local variable_name="$2"; local default_value="${3:-}"
  while true; do
    if [ -n "$default_value" ]; then
      read -r -p "$prompt_message [$default_value]: " input
      eval "$variable_name=\"${input:-$default_value}\""
    else
      read -r -p "$prompt_message: " input
      [ -z "$input" ] && { echo "Error: This field cannot be empty."; continue; }
      eval "$variable_name=\"$input\""
    fi
    break
  done
}
get_secret_input() {
  local prompt_message="$1"; local variable_name="$2"
  while true; do
    read -r -s -p "$prompt_message: " input; echo
    [ -z "$input" ] && { echo "Error: This field cannot be empty."; continue; }
    eval "$variable_name=\"$input\""; break
  done
}
err() { echo "❌ $*" >&2; exit 1; }
trim() { echo "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
sanitize_fname() { echo "$1" | sed -e 's/[^A-Za-z0-9_.-]/_/g'; }

# ---------- preflight ----------
[ "$EUID" -eq 0 ] && err "Please run as a sudo-capable user, not root."
command -v sudo >/dev/null || err "'sudo' is required."

echo "--- Medallion TAXII Server Installer (multi-collections, roles, sync automation) ---"
echo "DNS A record for your domain MUST point to this server's public IP."
echo

# ---------- inputs ----------
get_input        "FQDN for TAXII Server" DOMAIN_NAME
get_input        "Certbot email (for Let's Encrypt)" CERTBOT_EMAIL
# Users (roles)
get_input        "Admin username (read+write)" ADMIN_USER "taxii-admin"
get_secret_input "Admin password (HIDDEN)"     ADMIN_PASS
get_input        "Push-only username (write)"  PUSH_USER  "taxii-push"
get_secret_input "Push-only password (HIDDEN)" PUSH_PASS
get_input        "Pull-only username (read)"   PULL_USER  "taxii-pull"
get_secret_input "Pull-only password (HIDDEN)" PULL_PASS
# Collections list: name:mode items
get_input "Collections (comma-separated as name:mode, mode=push|pull|both)" COLLECTIONS_SPEC "misp-push:push,misp-pull:pull"
# Optional MISP tag filter
get_input "Optional MISP tag filter (e.g., tlp:white) or blank for all" FILTER_TAG ""

# Sync jobs (0..10)
get_input "How many TAXII sync jobs to create now? (0..10)" SYNC_COUNT "0"

# ---------- validate ----------
if ! [[ "$DOMAIN_NAME" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]; then
  err "Invalid domain name."
fi
if ! [[ "$CERTBOT_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
  err "Invalid email address."
fi
if ! [[ "$SYNC_COUNT" =~ ^([0-9]|10)$ ]]; then
  err "SYNC_COUNT must be between 0 and 10"
fi

# ---------- DNS sanity (optional) ----------
if command -v dig >/dev/null 2>&1; then
  HOST_IP="$(hostname -I | awk '{print $1}')"
  DNS_IPS="$(dig +short A "$DOMAIN_NAME")"
  if echo "$DNS_IPS" | grep -qx "$HOST_IP"; then
    echo "✅ DNS: $DOMAIN_NAME resolves to $HOST_IP"
  else
    echo "⚠️ DNS: $DOMAIN_NAME resolves to: $DNS_IPS (Certbot may fail)"
  fi
fi
echo "---------------------------------------------------------"

# ---------- install deps ----------
echo "1) Installing core dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx uuid-runtime dnsutils netcat-openbsd curl
sudo apt install -y mongodb || err "Failed to install 'mongodb' (consider 'mongodb-org' for prod)."
command -v mongod >/dev/null 2>&1 || err "'mongod' not found after install."

sudo systemctl enable mongod || true
sudo systemctl start  mongod || true
echo

# ---------- service user & venv ----------
echo "2) Creating service user & Python env..."
sudo useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$MEDALLION_USER" 2>/dev/null || true
sudo mkdir -p "$INSTALL_DIR"
sudo chown -R "$MEDALLION_USER":"$MEDALLION_USER" "$INSTALL_DIR"
sudo chmod 750 "$INSTALL_DIR"

cd "$INSTALL_DIR"
sudo -u "$MEDALLION_USER" python3 -m venv venv
VENV_BIN="$INSTALL_DIR/venv/bin"
VENV_PIP="$VENV_BIN/pip"

sudo -u "$MEDALLION_USER" "$VENV_PIP" install --upgrade pip wheel setuptools
sudo -u "$MEDALLION_USER" "$VENV_PIP" install "medallion~=$MEDALLION_VERSION" "pymongo~=$PYMONGO_VERSION" requests
echo

# ---------- collections: parse + stable IDs ----------
echo "3) Generating collections from spec: $COLLECTIONS_SPEC"
COLLECTIONS_DIR="$INSTALL_DIR/.collections"
sudo -u "$MEDALLION_USER" mkdir -p "$COLLECTIONS_DIR"

COLLECTIONS_JSON=""
COLLECTION_SUMMARY=""
IFS=',' read -r -a ITEMS <<< "$COLLECTIONS_SPEC"
for raw in "${ITEMS[@]}"; do
  item="$(trim "$raw")"
  name="${item%%:*}"
  mode="${item#*:}"
  name="$(trim "$name")"; mode="$(trim "$mode")"
  [[ -z "$name" || -z "$mode" ]] && err "Bad collection spec '$item' (expected name:mode)."
  case "$mode" in
    push) CAN_READ=false; CAN_WRITE=true ;;
    pull) CAN_READ=true;  CAN_WRITE=false ;;
    both) CAN_READ=true;  CAN_WRITE=true ;;
    *) err "Invalid mode '$mode' for collection '$name' (use push|pull|both)";;
  esac

  cid_file="$COLLECTIONS_DIR/.cid_$(sanitize_fname "$name")"
  if [ ! -f "$cid_file" ]; then
    sudo -u "$MEDALLION_USER" uuidgen | sudo -u "$MEDALLION_USER" tee "$cid_file" >/dev/null
  fi
  CID="$(sudo -u "$MEDALLION_USER" cat "$cid_file")"

  [ -n "$COLLECTIONS_JSON" ] && COLLECTIONS_JSON+=","
  COLLECTIONS_JSON+=$(cat <<J
{
  "name": "$name",
  "id": "$CID",
  "can_read": $CAN_READ,
  "can_write": $CAN_WRITE,
  "media_types": ["application/stix+json;version=2.1"],
  "title": "$name"
}
J
)
  COLLECTION_SUMMARY+="  - $name  |  id: $CID  |  mode: $mode"$'\n'
done
echo "Collections to create:"
echo "$COLLECTION_SUMMARY"
echo

# ---------- write medallion config ----------
echo "4) Writing Medallion config..."
sudo tee "$MEDALLION_CONFIG_FILE" >/dev/null <<EOF
{
  "users": {
    "$ADMIN_USER": { "password": "$ADMIN_PASS", "permissions": { "admin": true, "taxii": true } },
    "$PUSH_USER":  { "password": "$PUSH_PASS",  "permissions": { "taxii": true } },
    "$PULL_USER":  { "password": "$PULL_PASS",  "permissions": { "taxii": true } }
  },
  "taxii": {
    "api_roots": [
      {
        "name": "$API_ROOT",
        "url": "https://$DOMAIN_NAME/$API_ROOT/",
        "title": "MISP TAXII API Root",
        "description": "API Root for MISP STIX 2.1 exchange",
        "versions": ["taxii-2.1"],
        "collections": [ $COLLECTIONS_JSON ]
      }
    ],
    "persistence_api": {
      "module": "medallion.backends.mongodb_backend",
      "class": "MongoBackend",
      "parameters": {
        "mongo_host": "localhost",
        "mongo_port": 27017,
        "hashing_algorithm": "sha256"
      }
    }
  }
}
EOF
sudo chown root:"$MEDALLION_USER" "$MEDALLION_CONFIG_FILE"
sudo chmod 640 "$MEDALLION_CONFIG_FILE"
echo

# ---------- systemd for medallion ----------
echo "5) Systemd unit..."
sudo tee "$MEDALLION_SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Medallion TAXII 2.1 Server
After=network.target mongod.service network-online.target
Wants=network-online.target

[Service]
User=$MEDALLION_USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStartPre=/bin/sh -c 'for i in \$(seq 1 10); do nc -z localhost 27017 && exit 0; sleep 1; done; exit 1'
ExecStart=$INSTALL_DIR/venv/bin/medallion --host $TAXII_HOST_IP --port $TAXII_PORT --conf-file $MEDALLION_CONFIG_FILE
Restart=on-failure
RestartSec=2s
TimeoutStopSec=15
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
PrivateUsers=true
ReadWritePaths=$INSTALL_DIR
AmbientCapabilities=
CapabilityBoundingSet=
MemoryAccounting=true
MemoryMax=512M
TasksMax=512
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl is-active --quiet medallion || sudo systemctl start medallion
sudo systemctl enable medallion
echo

# ---------- nginx + TLS ----------
echo "6) Nginx reverse proxy (scoped paths) & Certbot..."
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN_NAME"
ACME_ROOT="/var/www/html"
sudo mkdir -p "$ACME_ROOT"; sudo chown -R www-data:www-data "$ACME_ROOT"
sudo rm -f /etc/nginx/sites-enabled/default

sudo tee "$NGINX_CONF" >/dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME;
    server_tokens off;
    location /.well-known/acme-challenge/ { root $ACME_ROOT; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME;
    server_tokens off;
    # certbot injects cert paths
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Referrer-Policy no-referrer-when-downgrade;
    add_header X-XSS-Protection "1; mode=block";
    add_header Permissions-Policy interest-cohort=();
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Forwarded-Port \$server_port;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_read_timeout 300s;
    client_max_body_size 10M;

    location = / { return 404; }
    location /taxii2/ { proxy_pass http://$TAXII_HOST_IP:$TAXII_PORT; }
    location /$API_ROOT/ { proxy_pass http://$TAXII_HOST_IP:$TAXII_PORT; }
    location / { return 404; }
}
EOF

sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
sudo nginx -t || err "Nginx configuration test failed."
sudo systemctl reload nginx

sudo certbot --nginx --non-interactive --agree-tos -m "$CERTBOT_EMAIL" -d "$DOMAIN_NAME" || err "Certbot failed."
sudo systemctl reload nginx
sudo systemctl enable --now certbot.timer || true
echo

# ---------- firewall ----------
echo "7) UFW rules..."
if command -v ufw >/dev/null 2>&1; then
  sudo ufw allow 'OpenSSH'
  sudo ufw allow 'Nginx Full'
  sudo ufw status | grep -q "Status: active" || sudo ufw --force enable
fi

# ---------- health check ----------
echo "8) Health check..."
STATUS="⚠️ Warning"; MSG="HTTPS health check failed; verify Nginx ↔ Medallion ↔ MongoDB."
if curl -fsS "https://$DOMAIN_NAME/taxii2/" >/dev/null; then STATUS="✅ Success"; MSG="Discovery /taxii2/ OK."
elif curl -fsS "https://$DOMAIN_NAME/$API_ROOT/" >/dev/null; then STATUS="✅ Success"; MSG="API Root /$API_ROOT/ OK."
fi
echo "$STATUS $MSG"
echo

# ---------- SYNC TOOL (requests already installed) ----------
echo "9) Installing TAXII sync tool & systemd templates..."
SYNC_DIR="$INSTALL_DIR/sync"
sudo -u "$MEDALLION_USER" mkdir -p "$SYNC_DIR"
sudo tee "$SYNC_DIR/taxii_sync.py" >/dev/null <<'PY'
#!/usr/bin/env python3
import os, sys, json, base64
from datetime import datetime, timezone
from urllib.parse import urljoin, urlencode
import requests

SRC_BASE      = os.environ["SRC_BASE"].rstrip("/") + "/"
SRC_COLL_ID   = os.environ["SRC_COLL_ID"]
SRC_USER      = os.environ["SRC_USER"]
SRC_PASS      = os.environ["SRC_PASS"]

DST_BASE      = os.environ["DST_BASE"].rstrip("/") + "/"
DST_COLL_ID   = os.environ["DST_COLL_ID"]
DST_USER      = os.environ["DST_USER"]
DST_PASS      = os.environ["DST_PASS"]

STATE_FILE    = os.environ.get("STATE_FILE", "/var/lib/taxii-sync/state.json")
VERIFY_TLS    = os.environ.get("VERIFY_TLS", "true").lower() != "false"
MAX_POST_BYTES = int(os.environ.get("MAX_POST_BYTES", str(9 * 1024 * 1024)))

S = requests.Session()
S.headers.update({"Accept": "application/taxii+json; version=2.1"})

def b64(u, p): return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
def iso_now(): return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
def load_state():
    try:
        with open(STATE_FILE,"r") as f: return json.load(f)
    except Exception: return {}
def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp,"w") as f: json.dump(state,f)
    os.replace(tmp, STATE_FILE)

def src_url(): return urljoin(SRC_BASE, f"collections/{SRC_COLL_ID}/objects/")
def dst_url(): return urljoin(DST_BASE, f"collections/{DST_COLL_ID}/objects/")

def taxii_get(added_after=None, next_token=None):
    params={}
    if added_after: params["added_after"]=added_after
    if next_token:  params["next"]=next_token
    url = src_url()
    if params: url = url + "?" + urlencode(params)
    r = S.get(url, headers={"Authorization": b64(SRC_USER,SRC_PASS)}, verify=VERIFY_TLS, timeout=120)
    r.raise_for_status()
    return r.json()

def bundles(objects, max_bytes):
    batch=[]
    for o in objects:
        test=batch+[o]
        blob=json.dumps({"objects":test},separators=(",",":")).encode()
        if len(blob)>max_bytes and batch:
            yield json.dumps({"objects":batch},separators=(",",":"))
            batch=[o]
        else:
            batch=test
    if batch:
        yield json.dumps({"objects":batch},separators=(",",":"))

def post_dst(payload):
    r = S.post(dst_url(), data=payload,
               headers={"Authorization": b64(DST_USER,DST_PASS),
                        "Content-Type":"application/taxii+json; version=2.1"},
               verify=VERIFY_TLS, timeout=300)
    r.raise_for_status()

def main():
    state=load_state()
    key=f"{SRC_BASE}|{SRC_COLL_ID}->{DST_BASE}|{DST_COLL_ID}"
    last=state.get(key,{}).get("added_after","1970-01-01T00:00:00Z")
    total_pulled=0; total_posted=0
    now=iso_now(); next_token=None
    while True:
        page=taxii_get(added_after=last, next_token=next_token)
        objs=page.get("objects",[]) or []
        more=bool(page.get("more")); next_token=page.get("next")
        total_pulled+=len(objs)
        if objs:
            for p in bundles(objs, MAX_POST_BYTES):
                post_dst(p)
                total_posted+=len(json.loads(p).get("objects",[]))
        if not more or not next_token: break
    state[key]={"added_after":now,"updated_at":iso_now(),"last_counts":{"pulled":total_pulled,"posted":total_posted}}
    save_state(state)
    print(f"pulled={total_pulled} posted={total_posted} next_since={now}")

if __name__=="__main__":
    try: main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr); sys.exit(1)
PY
sudo chmod +x "$SYNC_DIR/taxii_sync.py"

# systemd templates (service + timer)
sudo tee /etc/systemd/system/taxii-sync@.service >/dev/null <<'UNIT'
[Unit]
Description=TAXII collection sync (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/default/taxii-sync-%i
ExecStart=/opt/medallion/venv/bin/python /opt/medallion/sync/taxii_sync.py
User=medallion
Group=medallion
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/taxii-sync
CapabilityBoundingSet=
AmbientCapabilities=
UNIT

sudo tee /etc/systemd/system/taxii-sync@.timer >/dev/null <<'TIMER'
[Unit]
Description=Run TAXII sync (%i) on a schedule

[Timer]
OnCalendar=hourly
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
TIMER

sudo mkdir -p /var/lib/taxii-sync
sudo chown "$MEDALLION_USER":"$MEDALLION_USER" /var/lib/taxii-sync
sudo chmod 750 /var/lib/taxii-sync

# ---------- prompt for sync jobs ----------
if [ "$SYNC_COUNT" != "0" ]; then
  echo "Configuring $SYNC_COUNT sync job(s)..."
  for i in $(seq 1 "$SYNC_COUNT"); do
    echo "--- Sync job #$i ---"
    get_input        "Source BASE (e.g. https://src.domain/$API_ROOT/)" SRC_BASE
    get_input        "Source Collection ID (UUID)"                       SRC_COLL_ID
    get_input        "Source user"                                       SRC_USER
    get_secret_input "Source password (HIDDEN)"                          SRC_PASS

    get_input        "Destination BASE (e.g. https://dst.domain/$API_ROOT/)" DST_BASE
    get_input        "Destination Collection ID (UUID)"                     DST_COLL_ID
    get_input        "Destination user"                                     DST_USER
    get_secret_input "Destination password (HIDDEN)"                        DST_PASS

    get_input        "State filename (default: state-$i.json)" STATE_NAME "state-$i.json"
    get_input        "OnCalendar schedule (systemd, default: hourly)" SYNC_CAL "hourly"
    get_input        "Max POST size bytes (default 9000000)" MAX_POST "9000000"
    get_input        "Verify TLS? true/false (default: true)" VERIFY_TLS "true"

    ENV_FILE="/etc/default/taxii-sync-$i"
    sudo tee "$ENV_FILE" >/dev/null <<EOF
SRC_BASE="$SRC_BASE"
SRC_COLL_ID="$SRC_COLL_ID"
SRC_USER="$SRC_USER"
SRC_PASS="$SRC_PASS"
DST_BASE="$DST_BASE"
DST_COLL_ID="$DST_COLL_ID"
DST_USER="$DST_USER"
DST_PASS="$DST_PASS"
STATE_FILE="/var/lib/taxii-sync/$STATE_NAME"
VERIFY_TLS="$VERIFY_TLS"
MAX_POST_BYTES="$MAX_POST"
EOF
    sudo chmod 640 "$ENV_FILE"

    # If a custom schedule was provided, create an override timer drop-in
    if [ "$SYNC_CAL" != "hourly" ]; then
      sudo mkdir -p /etc/systemd/system/taxii-sync@$i.timer.d
      sudo tee /etc/systemd/system/taxii-sync@$i.timer.d/override.conf >/dev/null <<EOF
[Timer]
OnCalendar=$SYNC_CAL
RandomizedDelaySec=300
Persistent=true
EOF
    fi

    sudo systemctl daemon-reload
    sudo systemctl enable --now "taxii-sync@$i.timer"
    # test-run once
    sudo systemctl start "taxii-sync@$i.service"
  done
fi

# ---------- summary ----------
ADMIN_B64=$(echo -n "$ADMIN_USER:$ADMIN_PASS" | base64)
PUSH_B64=$(echo -n "$PUSH_USER:$PUSH_PASS" | base64)
PULL_B64=$(echo -n "$PULL_USER:$PULL_PASS" | base64)
[ -z "${FILTER_TAG:-}" ] && FILTER_JSON='{}' || FILTER_JSON="{\"tags\": [\"$FILTER_TAG\"]}"

echo ""
echo "=========================================================="
echo "🚀 PRODUCTION TAXII Server Deployment COMPLETE"
echo "=========================================================="
echo "URL:   https://$DOMAIN_NAME"
echo "State: $(sudo systemctl is-active medallion)"
echo
echo "Users (Base64 keys):"
echo "  • Admin (rw): $ADMIN_USER  =>  $ADMIN_B64"
echo "  • Push  (w):  $PUSH_USER   =>  $PUSH_B64"
echo "  • Pull  (r):  $PULL_USER   =>  $PULL_B64"
echo
echo "Collections created from spec:"
echo "$COLLECTIONS_SPEC"
echo
echo "MISP example:"
echo "  URL=https://$DOMAIN_NAME  API Root=$API_ROOT  Filter=$FILTER_JSON"
echo "  Use appropriate user/key & collection per action."
echo
if [ "$SYNC_COUNT" != "0" ]; then
  echo "Sync jobs enabled:"
  for i in $(seq 1 "$SYNC_COUNT"); do
    echo "  • taxii-sync@$i.timer  (view: sudo systemctl list-timers | grep taxii-sync@$i)"
  done
  echo "Check logs:"
  echo "  sudo journalctl -u taxii-sync@1 -f"
fi
echo "Medallion logs: sudo journalctl -u medallion -f"
echo "Nginx reload:   sudo nginx -t && sudo systemctl reload nginx"
echo "=========================================================="
