# Misp Taxii Server Setup (Setup Guide for Installer)

## 1. Overview

This document explains how to deploy a secure, production-ready TAXII 2.1 server using Medallion, behind HTTPS with Nginx, hardened with systemd sandboxing. It also supports multiple TAXII collections, separate push/pull/admin users, and automated syncing between collections using a built-in sync tool.

The deployment is fully automated using the script:

`misp_taxii_prod_final_with_sync.sh`

---

## 2. Key Features

| Feature                     | Description                                                                 |
| --------------------------- | --------------------------------------------------------------------------- |
| Secure TAXII 2.1 server     | Powered by Medallion, bound to localhost, reverse-proxied by Nginx with TLS |
| Multi-user roles            | Admin (read/write), push-only (producer), pull-only (consumer)              |
| Multiple collections        | Each can be configured as push-only, pull-only, or both                     |
| Systemd service hardening   | Private filesystems, no new privileges, resource limits                     |
| TLS via Let's Encrypt       | Auto-renewal using certbot.timer                                            |
| Incremental collection sync | Optional jobs: source → destination collections                             |
| Supports multiple sync jobs | Each job can sync different collections or servers                          |
| Logs & monitoring           | Systemd journal integration                                                 |

---

## 3. Requirements

| Component | Requirement                                      |
| --------- | ------------------------------------------------ |
| OS        | Ubuntu 20.04/22.04 or Debian-based distributions |
| User      | Must run script as non-root with sudo privileges |
| Network   | Open ports 80 (for Certbot) and 443 (for HTTPS)  |
| DNS       | Domain must resolve to this server’s public IP   |
| Storage   | ~1 GB recommended                                |
| Python    | Installed automatically (python3 + venv)         |

---

## 4. Installation Steps

1. Upload the installer to the server:

   ```
   scp misp_taxii_prod_final_with_sync.sh user@server:/tmp/
   ```

2. Log in and run:

   ```
   cd /tmp
   chmod +x misp_taxii_prod_final_with_sync.sh
   ./misp_taxii_prod_final_with_sync.sh
   ```

3. Follow prompts:

   * Enter domain (e.g., taxii.yourdomain.com)
   * Email for SSL certificate
   * Create admin, push, and pull users
   * Define collections like: `misp-prod:push,cti-feed:pull,shared:both`
   * Choose number of sync jobs (0 = skip)

---

## 5. User Roles and API Keys

| Username    | Permissions      | Typical Use            |
| ----------- | ---------------- | ---------------------- |
| taxii-admin | Full admin+taxii | Management/debugging   |
| taxii-push  | Write-only       | MISP pushes indicators |
| taxii-pull  | Read-only        | Clients pulling STIX   |

API authentication uses HTTP Basic Auth, typically provided as Base64.

Example:

```
echo -n "taxii-push:password" | base64
```

Use this in MISP or external clients as the "API Key".

---

## 6. Collection Configuration (during setup)

You will provide a comma-separated list formatted as:

```
name:mode
```

Where `mode` is:

* `push` → can_write=true, can_read=false
* `pull` → can_write=false, can_read=true
* `both` → both true

Example prompt input:

```
misp-intel:push,global-shared:both,external-feed:pull
```

Each will receive a persistent Collection ID.

---

## 7. Optional TAXII Sync Jobs (Cross-collection replication)

If you enter a number > 0, you will configure sync jobs like:

| Sync Job | Direction | Example                                           |
| -------- | --------- | ------------------------------------------------- |
| Job 1    | A → B     | Pulls from collection in server A and pushes to B |
| Job 2    | B → C     | Independent job                                   |

Each job generates:

* `/etc/default/taxii-sync-N` (environment file)
* `taxii-sync@N.service` (manual run)
* `taxii-sync@N.timer` (scheduled run, default hourly)

To manually run a sync:

```
sudo systemctl start taxii-sync@1.service
```

To view logs:

```
sudo journalctl -u taxii-sync@1 -f
```

---

## 8. Verifying Installation

Check Medallion service:

```
sudo systemctl status medallion
```

Check TAXII root:

```
curl -k https://yourdomain/taxii2/
```

Check specific API root:

```
curl -u taxii-admin:password -k https://yourdomain/api-root-1/
```

---

## 9. MISP Configuration Example

In **Sync Actions → List TAXII Servers → Add TAXII Server:**

| Field           | Value                                  |
| --------------- | -------------------------------------- |
| URL             | `https://yourdomain`                   |
| API Root        | `api-root-1`                           |
| API Key         | `<Base64 of taxii-push:password>`      |
| Collection Name | e.g., `misp-intel`                     |
| Filter JSON     | `{}` or e.g. `{"tags": ["tlp:white"]}` |

---

## 10. MongoDB Authentication (Optional Hardening)

Currently, MongoDB allows local access without auth.

To enable secure auth:

1. Create users:

```
sudo mongo
use admin
db.createUser({ user: "medallion_user", pwd: "StrongPass!", roles: ["readWrite", "dbAdmin"] })
```

2. Edit `/etc/mongod.conf`:

```
security:
  authorization: enabled
```

3. Restart:

```
sudo systemctl restart mongod
```

4. Update `/opt/medallion/config.json`:
   Replace:

```
"mongo_host": "localhost",
"mongo_port": 27017,
```

With:

```
"mongo_uri": "mongodb://medallion_user:StrongPass!@localhost:27017/medallion?authSource=admin",
```

5. Restart Medallion:

```
sudo systemctl restart medallion
```

---

## 11. System Maintenance & Logs

| Task                | Command                              |                  |
| ------------------- | ------------------------------------ | ---------------- |
| Check TAXII service | `sudo systemctl status medallion`    |                  |
| Tail logs           | `sudo journalctl -u medallion -f`    |                  |
| Restart service     | `sudo systemctl restart medallion`   |                  |
| List sync timers    | `sudo systemctl list-timers          | grep taxii-sync` |
| Tail sync logs      | `sudo journalctl -u taxii-sync@1 -f` |                  |
| Test Nginx          | `sudo nginx -t`                      |                  |
| Reload Nginx        | `sudo systemctl reload nginx`        |                  |
| Renew SSL manually  | `sudo certbot renew --dry-run`       |                  |

---

## 12. Final Summary for MISP Admin

Provide the following to your MISP administrator:

* TAXII Server URL: `https://yourdomain`
* API Root: `api-root-1`
* Collection Name(s): from your created list
* API Key: (Base64 form of `taxii-push:password`)
* Optional filter JSON: e.g. `{}` or `{"tags": ["some-tag"]}`

---

## 13. Creating a New Admin User on Linux

This guide explains how to create a new user and grant them sudo (administrator) privileges.

---

📍 Step 1: Add a New User

```bash
adduser adminuser
You will be prompted to enter a password and some optional user details.

📍 Step 2: Add the User to the sudo Group
bash
Copy code
usermod -aG sudo adminuser
This grants the new user administrative (sudo) privileges.

📍 Step 3: Switch to the New User
bash
Copy code
su - adminuser
This command switches the current session to the new user with their environment loaded.

✅ Optional: Verify Sudo Access
Once logged in as the new user, run:

bash
Copy code
sudo whoami
If the result is root, the configuration is successful.

---

## 14. You’re Done! ✅

Your TAXII server is now running securely with collections, role-based access, TLS, optional auto-sync, systemd hardening, and monitoring readiness.
