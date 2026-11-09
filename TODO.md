# TODO

Stand: 09.11.2026. Reihenfolge = Abhängigkeiten.

## 1. Nexus: Docker-Registry erreichbar machen (blockiert das Release)

`https://repository.jaycloud.at/v2/` liefert **404**. Docker spricht eine Registry immer unter `/v2/` am Host an,
deshalb bricht der Release-Workflow im ersten Schritt ab, und es gibt noch kein Image. Nexus stellt das
Docker-API bereits unter `/repository/rtl.over.internet/v2/` bereit (dort 401), es fehlt nur der Weg über `/v2/`.

- [ ] Nexus → Settings → Repositories → `rtl.over.internet` → Repository Connectors: **HTTP-Port `8082`**
      (läuft Nexus im Docker: Port auf dem Host veröffentlichen, z. B. `127.0.0.1:8082:8082`)
- [ ] Nexus → Security → Realms: **„Docker Bearer Token Realm“** aktivieren
- [ ] nginx vor `repository.jaycloud.at`, im bestehenden `server`-Block:
      ```nginx
      location /v2/ {
          proxy_pass http://127.0.0.1:8082;
          proxy_set_header Host $host;
          proxy_set_header X-Forwarded-Proto https;
          proxy_set_header X-Forwarded-For $remote_addr;
          client_max_body_size 0;
          proxy_request_buffering off;
          proxy_read_timeout 600s;
      }
      ```
      `nginx -t && systemctl reload nginx`
- [ ] Prüfen: `curl -sI https://repository.jaycloud.at/v2/` → **401** mit `WWW-Authenticate: Bearer …`
- [ ] Rechte: Runner-Benutzer (`NEXUS_USER`) braucht Push auf `rtl.over.internet`; für den Server
      Lese-Benutzer oder „Allow anonymous docker pull“

Details: [docs/release.md](docs/release.md)

## 2. Release bauen

- [ ] Release-Workflow neu starten: `gh run rerun --failed -R JayLo1401/rtl.over.internet <run-id>` oder
      Actions → Release → „Run workflow“
- [ ] Erwartet: Tag `v0.1.0`, Image `repository.jaycloud.at/rtl.over.internet/rtl-over-internet:0.1.0` und `:latest`

## 3. Auf den Server (Hetzner, Arcane)

Anleitung: [docs/arcane.md](docs/arcane.md)

- [ ] DNS `rtl.jaycloud.at` (A + AAAA)
- [ ] Hetzner-Firewall: TCP 80/443, **UDP 3478–3479** eingehend
- [ ] `/opt/rtl.over.internet/data` anlegen, `chown 10001:10001`, `chmod 700`
- [ ] nginx + certbot für `rtl.jaycloud.at` ([docs/nginx-rtl.jaycloud.at.conf](docs/nginx-rtl.jaycloud.at.conf))
- [ ] Arcane: Registry `repository.jaycloud.at` hinterlegen (falls kein anonymer Pull)
- [ ] Arcane: Projekt `rtl-over-internet` mit `docker-compose.yml` und `.env` (Vorlage `.env.example`,
      mindestens `ROI_ADMIN_PASSWORD`, `ROI_DATA_PATH=/opt/rtl.over.internet/data`)
- [ ] Prüfen: `curl -sI https://rtl.jaycloud.at/healthz` → 204, `ss -ulpn | grep -E ':347[89]'`

## 4. Optional: Anmeldung über authentik

- [ ] In authentik „OAuth2/OpenID Provider“ (confidential), Redirect-URI `https://rtl.jaycloud.at/login/oidc/callback`
- [ ] In `.env`: `ROI_OIDC_ISSUER`, `ROI_OIDC_CLIENT_ID`, `ROI_OIDC_CLIENT_SECRET`,
      `ROI_OIDC_ALLOWED_EMAILS` (oder `ROI_OIDC_ALLOWED_GROUPS`)

## 5. Umstellen und Feldtest

- [ ] rtltcp.server (HA und Windows) von `http://192.168.100.101:8090` auf `https://rtl.jaycloud.at` umstellen
      (Instanz in der neuen Weboberfläche anlegen, an beiden Servern neu hinzufügen)
- [ ] Test-Vermittler auf dem Windows-Rechner beenden: Prozess auf Port 8090 stoppen
      (Start/Log/Passwort liegen in `data/`, nicht im Repo)
- [ ] Stufe 3 aus [docs/testing.md](docs/testing.md): ein Standort in einem anderen Netz (z. B. Handy-Hotspot),
      IPv6/CGNAT, 10 min Stream, Traffic auf Hetzner nur wenige kB → Ergebnisse in #6 und #4

## Nebenbei

- [ ] Dependabot-PRs (actions/checkout, docker/setup-qemu-action, docker/login-action) mergen, wenn grün
- [ ] Alembic statt der kleinen Spaltenmigration in `app/db.py`, sobald sich das Schema weiter ändert
