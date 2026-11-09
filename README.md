# rtl.over.internet

Vermittler zum Teilen von RTL-SDR-Sticks zwischen `rtltcp.server`-Installationen über das Internet,
ohne VPN und ohne Portfreigabe. Der Dienst übernimmt Anmeldung, Berechtigung und Verbindungsaufbau
(Signalisierung und Rendezvous wie bei STUN). **Der Stream läuft direkt zwischen den Standorten (QUIC über UDP,
Hole-Punching) und nie über diesen Dienst.** Ein Relay gibt es nicht.

- Schnittstelle zu `rtltcp.server`: [docs/protocol.md](docs/protocol.md)
- Übersicht und Aufgaben: Issue #1

## Funktionen

- Weboberfläche für den Admin: Instanzen anlegen, umbenennen, deaktivieren, löschen, Code und Passwort neu erzeugen,
  verbundene Server, Freigaben und Stream-Sitzungen ansehen, Server trennen oder widerrufen, Sitzungen beenden, Audit-Log
- **Instanz** = Freigabegruppe. Jede Instanz hat einen Code (z. B. `K7QM-4XPD`) und ein erzeugtes Passwort.
  Beides gibt man zusammen weiter; der Admin kann es jederzeit ansehen und als Textdatei herunterladen.
  Mit dem Admin-Passwort kann man sich ebenfalls an jeder Instanz anmelden.
- Export aller Daten als JSON (Instanzen samt Passwörtern, Geräte, Freigaben, Sitzungen, Audit-Log).
  Der Dienst ist für einen einzelnen Betreiber gedacht: Der Admin sieht alles.
  Der Admin kann sich zusätzlich mit seinen eigenen Zugangsdaten an jeder Instanz anmelden.
- Enrollment (`POST /api/v1/enroll`), Steuerkanal (`wss://…/api/v1/control`), Rendezvous (UDP 3478 + 3479)

## Sicherheit

- Passwörter mit Argon2id, Geräte- und Sitzungs-Tokens nur als SHA-256-Hash gespeichert
- Instanz-Passwörter zusätzlich mit AES-256-GCM verschlüsselt (Schlüssel aus `ROI_SECRET_KEY` bzw. `/data/secret_key`),
  damit der Admin sie abrufen kann. Ohne den Schlüssel sind sie aus einer Datenbank-Kopie nicht lesbar.
  Wechselt der Schlüssel, sind sie nicht mehr abrufbar (dann „Neues Passwort“).
- Rate-Limit und Sperre (15 min) bei Fehlversuchen pro IP und pro Admin-Benutzer bzw. Instanz-Code, für Web-Login und Enrollment
- Gleiche Fehlermeldung und gleiche Laufzeit für falschen Code oder falsches Passwort
- Sitzungs-Cookie `HttpOnly`, `SameSite=Strict`, bei `https` als `__Host-…` mit `Secure`; 30 min Leerlauf, max. 8 h
- CSRF-Token in allen Formularen, CSP ohne Inline-Skripte und -Styles, `X-Frame-Options: DENY`, HSTS bei https
- Keine Stacktraces nach außen, keine API-Doku, `/healthz` ohne Inhalt
- Rendezvous antwortet nur auf HMAC-signierte Anfragen laufender Sitzungen, Antwort nie größer als die Anfrage
- WebSocket-Nachrichten max. 64 KiB, Rate-Limit pro Verbindung
- Container läuft nicht als root, mit read-only Root-FS, Daten nur in `/data`
- Audit-Log: Logins, Fehlversuche, Enrollment, alle Änderungen an Instanzen und Geräten, Stream-Sitzungen

## Konfiguration

| Variable | Standard | Bedeutung |
|---|---|---|
| `ROI_ADMIN_USER` | – | Admin-Benutzer (Pflicht außer bei `ROI_AUTH_MODES=oidc`) |
| `ROI_ADMIN_PASSWORD` / `ROI_ADMIN_PASSWORD_FILE` | – | Admin-Passwort, mind. 12 Zeichen (Pflicht außer bei `oidc`). Wird beim Start gesetzt, gespeichert wird nur der Hash. |
| `ROI_PUBLIC_URL` | `http://localhost:8090` | öffentliche Adresse, z. B. `https://rtl.jaycloud.at` |
| `ROI_AUTH_MODES` | `all` | `all` (Passwort + OIDC), `internal` (nur Passwort), `oidc` (nur OIDC, kein Admin-Passwort nötig) |
| `ROI_OIDC_ISSUER`, `ROI_OIDC_CLIENT_ID`, `ROI_OIDC_CLIENT_SECRET` | leer | OpenID Connect (authentik, wie bei order.manager). Redirect-URI: `<ROI_PUBLIC_URL>/login/oidc/callback` |
| `ROI_OIDC_ALLOWED_EMAILS` / `ROI_OIDC_ALLOWED_GROUPS` | leer | wer per OIDC hinein darf (Pflicht, sobald OIDC konfiguriert ist; jede OIDC-Anmeldung ist Admin) |
| `ROI_OIDC_BUTTON_LABEL` | `Mit authentik anmelden` | Text des Buttons |
| `ROI_TRUSTED_PROXIES` | leer | IPs/Netze, von denen `X-Forwarded-For` übernommen wird (nginx) |
| `ROI_SECRET_KEY` | erzeugt | Schlüssel für CSRF-Tokens (mind. 32 Zeichen). Fehlt er, wird er in `/data/secret_key` angelegt. |
| `ROI_COOKIE_SECURE` | aus URL | `Secure`-Cookie; Standard: an bei `https://`-URL, sonst aus (lokaler Test) |
| `ROI_HTTP_HOST` / `ROI_HTTP_PORT` | `127.0.0.1` / `8090` | Adresse der Weboberfläche |
| `ROI_RENDEZVOUS_BIND` | `::` | Adresse für UDP (`::` = IPv4 und IPv6) |
| `ROI_RENDEZVOUS_PORTS` | `3478,3479` | genau zwei UDP-Ports (NAT-Erkennung) |
| `ROI_RENDEZVOUS_HOST` | Host aus URL | Hostname, den die Server für das Rendezvous nutzen |
| `ROI_DATA_DIR` | `/data` | SQLite-Datenbank und Schlüssel |
| `ROI_TIMEZONE` | `Europe/Vienna` | Zeitzone der Anzeige |

## Installation auf dem Server (Hetzner, rtl.jaycloud.at)

1. DNS: `A`- und `AAAA`-Eintrag für `rtl.jaycloud.at` auf den Server.
2. Firewall (Hetzner Cloud Firewall **und** ggf. `ufw`): TCP 80, 443 sowie **UDP 3478–3479** eingehend erlauben.
   ```sh
   ufw allow 3478:3479/udp
   ```
3. Dateien ablegen, Konfiguration und Datenverzeichnis anlegen (Container läuft als UID 10001):
   ```sh
   git clone https://github.com/JayLo1401/rtl.over.internet.git /opt/rtl.over.internet
   cd /opt/rtl.over.internet
   cp .env.example .env
   sed -i "s|^ROI_ADMIN_PASSWORD=.*|ROI_ADMIN_PASSWORD=$(openssl rand -base64 24)|" .env   # oder von Hand setzen
   chmod 600 .env
   mkdir -p data && chown 10001:10001 data && chmod 700 data
   docker login repository.jaycloud.at   # nur, wenn das Repository keinen anonymen Pull erlaubt
   docker compose pull && docker compose up -d
   ```
   Das Image kommt aus dem Release-Workflow (siehe [docs/release.md](docs/release.md)).
   `docker-compose.yml` nutzt `network_mode: host`, damit der Rendezvous-Endpunkt die echte Absenderadresse sieht
   (kein Docker-Portmapping, kein IPv6→IPv4-Proxy). Die Weboberfläche lauscht dadurch nur auf `127.0.0.1:8090`.
4. nginx und Zertifikat: [docs/nginx-rtl.jaycloud.at.conf](docs/nginx-rtl.jaycloud.at.conf) nach
   `/etc/nginx/sites-available/` kopieren, verlinken, `certbot certonly --webroot -w /var/www/certbot -d rtl.jaycloud.at`,
   `nginx -t && systemctl reload nginx`. Wichtig: WebSocket-Upgrade und `proxy_read_timeout 1h` für `/api/v1/control`.
5. Anmelden unter `https://rtl.jaycloud.at` mit `admin` und dem Passwort aus `.env` (`ROI_ADMIN_PASSWORD`).

Update: `docker compose pull && docker compose up -d`. Backup: Verzeichnis `data/` (SQLite).
Releases entstehen automatisch bei jedem Push auf `main`, siehe [docs/release.md](docs/release.md).
Betrieb über Arcane: [docs/arcane.md](docs/arcane.md).
Testablauf: [docs/testing.md](docs/testing.md).

## Lokaler Test

Nativ (empfohlen, damit reflexive Adressen stimmen), Python 3.11 oder neuer:

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements-dev.txt
$env:ROI_DATA_DIR = ".\data"
$env:ROI_ADMIN_USER = "admin"
$env:ROI_ADMIN_PASSWORD = "mindestens-12-zeichen"
$env:ROI_PUBLIC_URL = "http://192.168.100.10:8090"   # LAN-Adresse dieses Rechners
$env:ROI_HTTP_HOST = "0.0.0.0"
.\.venv\Scripts\python -m app
```

Oder im Docker (Docker Desktop): `docker compose -f docker-compose.local.yml up --build` mit denselben Variablen.
Docker Desktop leitet UDP über einen Proxy, reflexive Adressen und NAT-Typ sind dann nicht aussagekräftig.

Die `rtltcp.server` melden sich dann an `http://<LAN-IP>:8090` an (Steuerkanal `ws://<LAN-IP>:8090/api/v1/control`).
Unter Windows ggf. TCP 8090 und UDP 3478–3479 in der Windows-Firewall freigeben.

## Entwicklung

```sh
pip install -r requirements-dev.txt
python -m pytest
```

Datenbankschema wird beim Start per `create_all` angelegt. Alembic-Migrationen folgen, sobald sich das Schema ändert.
