# Inventory Audit — Internal Blind-Count MVP

Self-hosted, mobile-friendly inventory auditing application with team assignments, blind physical counts, administrator-only expected quantities, discrepancy reporting, recounts, CSV exports and a team leaderboard.

## Licensing and permitted use

**Copyright © 2026. All rights reserved.**

- **Personal use:** Free for personal, non-commercial use, subject to the copyright holder's permission and any applicable license terms.
- **Business, organizational, or enterprise use:** Requires prior written permission and a separate license from the copyright holder, whether the deployment is internal, self-hosted, or commercial.
- **No implied enterprise license:** Access to this repository or source code does not grant permission to deploy, redistribute, sublicense, or commercially use the software.
- **Exceptions:** The copyright holder may grant specific organizations free or discounted use through written authorization.

For licensing or permission requests, contact the repository owner. This README notice is not a substitute for a complete license agreement; no open-source license is granted by this notice.

## Features
- Admin creates teams, users and audit runs.
- Import `sku,description,location,expected_qty` CSV into a **draft** audit.
- Assign selected SKUs or all audit parts to one or more teams; each team can independently count the same items.
- Employees see **only** SKU, description, location, audit and submission status; previously submitted quantities are not displayed. Expected quantities are never included in employee pages.
- Admin can activate/close an audit, see expected vs counted quantities and download reconciliation CSV.
- Admin can request recounts; original count history is preserved.
- Leaderboard counts completed part lines (not unit quantities).
- Session authentication, password hashing, CSRF protection, secure cookie option, server-side role checks, security headers and event logging.

## Quick start (Docker)
1. Install Docker Engine and Docker Compose on a dedicated internal Linux VM.
2. Copy `.env.example` to `.env`. Generate a secret with `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'` and set `SECRET_KEY`.
3. Keep `BIND_IP=127.0.0.1` until the HTTPS reverse proxy and firewall are configured. Keep `COOKIE_SECURE=true` for HTTPS.
4. Run `docker compose up -d --build`.
5. Bootstrap an admin using an ephemeral environment variable (avoid saving the password in `.env`):
   ```bash
   docker compose exec -e ADMIN_USERNAME=admin -e ADMIN_PASSWORD='CHANGE_THIS_TO_A_LONG_UNIQUE_PASSWORD' inventory flask --app app create-admin
   ```
6. Configure internal DNS (for example `inventory.company.internal`) and an HTTPS reverse proxy to `127.0.0.1:8000` on the same host. Use an internally trusted certificate. Allow only the authorized corporate Wi-Fi subnet(s) to reach HTTPS; deny guest Wi-Fi, other VLANs, VPN paths unless explicitly authorized, and the public internet.
7. Open the internal HTTPS URL, log in, create a team, create a counter account, create an audit, import `sample_inventory.csv`, assign the team, activate the audit, and submit counts from a separate counter login.

**Network requirement:** This app cannot determine whether a device is physically on company Wi-Fi. Wi-Fi-only access must be enforced by network segmentation, firewall ACLs, routing and private DNS. A device on an allowed subnet can reach the app even if it is connected by Ethernet; use NAC/802.1X and VLAN policy if strict Wi-Fi membership matters.

## Reverse proxy example (Nginx on same host)
```nginx
server {
    listen 443 ssl;
    server_name inventory.company.internal;
    ssl_certificate /etc/ssl/internal/inventory.crt;
    ssl_certificate_key /etc/ssl/internal/inventory.key;
    allow 10.20.30.0/24; # REPLACE with the real authorized Wi-Fi subnet
    deny all;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```
Ensure firewall blocks direct access to port 8000. Do not enable `TRUST_PROXY` unless you understand and constrain trusted proxy traffic. TLS certificates must be trusted by employee devices.

## Workflow
1. Admin creates team(s) and user accounts.
2. Admin creates a draft audit and imports CSV inventory.
3. Admin assigns selected SKUs to a team, or leaves the SKU field blank to assign all parts; repeat for additional teams.
4. Admin activates audit; counts become available.
5. Counters submit one initial count per assigned part. Counts are immutable; admin can request a recount.
6. Admin reviews discrepancies and exports CSV; closes audit when finished.

## Data and backup
SQLite database lives in Docker volume `audit_data` at `/data/inventory.db`. Back it up with SQLite's online backup API or a coordinated stopped-container volume backup. Test restores. Backups include expected inventory and personnel records; restrict and encrypt them. Retain an off-host copy. Do not commit `.env`, production databases or exports to GitHub.

## Limitations / production hardening
This is a deployable **MVP**, not a certified audit platform. Before a high-stakes audit, add independent recount assignment (currently recount goes to the original team), bulk assignment editing/removal, user deactivation/password resets, MFA/Entra SSO, rate limiting, centralized monitoring, database migrations, immutable append-only audit event storage, signed audit closeout, exports of the full count history, and automated restore testing. Audit-specific part descriptions and locations are snapshotted at import; existing historical audit items keep their original descriptions and locations. The leaderboard counts assignment completion only for active audits. This application does not update a master ERP or inventory ledger.

## Local development
```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY=$(python -c 'import secrets;print(secrets.token_urlsafe(48))')
export DATABASE=./inventory.db
export COOKIE_SECURE=false
flask --app app create-admin # set ADMIN_PASSWORD first
flask --app app run --host 127.0.0.1
```
Never expose the Flask development server to a company network.

## License
Internal use. Review and adapt security, retention, backup, and access policies before production deployment.

## Leaderboard visibility
All authenticated users (employees and administrators) can open `/leaderboard` from the navigation bar or the dashboard banner. Rankings show assigned part lines, completed part lines, and completion percentage, never expected stock quantities or variance. The application remains private to the configured company network.

## Reviewed changes (v3)
- Leaderboard now filters out closed/draft audit assignments from both numerator and denominator.
- Employees see submission status without previous count quantities. This does not yet implement independent blind recounts.
- Added 5-failed-attempt / 15-minute username lockout; also deploy IP-based reverse proxy rate limiting and monitor denial-of-service risk.
- Audit-specific description and location snapshots are retained even when the master parts catalog changes.
- CSV export protects text cells against spreadsheet formula injection.
- Prevent duplicate outstanding recount requests.
- `backup.py` creates a consistent SQLite online backup; schedule it, copy backups off-host, encrypt and test restores. Example: `docker compose exec inventory python backup.py /data/backups`.
- Application syntax and project archive validated. Flask runtime and Docker integration tests could not be run in the build environment; do not treat as production verified.

**Known limitations:** Independent recount team assignment, Entra/MFA, immutable external audit logs, robust account administration, complete automated integration tests, backup scheduling and recovery drills remain necessary before a formal production audit. SQLite write concurrency also limits large simultaneous counts.

## v4: Registration, invitations, password resets and individual assignments

- **Self-registration:** set `ALLOW_SELF_REGISTRATION=true` in `.env`. Employees use `/register`; accounts remain unapproved until an admin approves them. Admins then assign teams using the Users section.
- **Invitation:** admins select **Create invitation link**. A one-use, 24-hour link is shown once; send it privately. Invitation accounts are approved automatically but start without a team. Admins may assign them a team afterward.
- **Admin password reset:** use **Reset password** beside a user. A one-use, 24-hour reset link is generated. Share privately; do not post it in public chat or a ticket.
- **Individual assignments:** while an audit is in draft, open the audit, choose an approved employee, and enter comma-separated SKUs (or leave blank for all). Directly assigned parts appear under **Assigned directly to me**. Employees cannot submit for another employee's direct assignment. Individual results are included in the admin audit screen and CSV export.
- **Leaderboard:** individual assignments are credited to the employee's current team, if assigned, alongside team-wide assignments. All authenticated users can see the leaderboard.

### Important operational notes

- Direct and team assignments are distinct counting tasks; assigning the same SKU both ways intentionally produces two independent counts. The CSV includes both records, not a summed stock quantity.
- Password reset links and invitations are **not emailed automatically**; an admin copies and distributes them securely.
- Registration is disabled unless explicitly enabled in `.env`. Company Wi-Fi access still requires reverse-proxy/firewall controls; the app itself cannot identify company Wi-Fi securely.
- Password resets do not revoke other existing browser sessions; deploy behind a trusted HTTPS reverse proxy and consider centralized SSO and session revocation before production.
- SQLite should be backed up regularly; see `backup.py`. Review logs, permissions, rate limits and recovery tests before using for formal audits.
