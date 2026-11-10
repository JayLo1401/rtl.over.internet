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
  Beides gibt man zusammen weiter; es ist jederzeit auf der Seite der Instanz abrufbar.
  Mit dem Admin-Passwort kann man sich ebenfalls an jeder Instanz anmelden.
- Zugangsdatei (JSON) pro Instanz zum Hochladen im rtltcp.server, damit nichts abgeschrieben werden muss
- Benutzer und Rechte:
  - **Systemadmin** (Admin aus der `.env` oder OIDC-Gruppe `ROI_OIDC_ADMIN_GROUPS`): alles, auch Benutzer verwalten
  - **Instanz-Admin**: verwaltet die zugewiesene Instanz (außer löschen), kann woanders auch nur Benutzer sein
  - **Benutzer**: sieht die zugewiesene Instanz mit Zugangsdaten und Status und lädt die Zugangsdatei herunter
  - Lokale Benutzer legt der Systemadmin an, OIDC-Benutzer (`ROI_OIDC_USER_GROUPS`) erscheinen nach der ersten
    Anmeldung. Neue Benutzer haben keine Rechte, bis ihnen Instanzen zugewiesen werden.
- Export aller Daten als JSON (nur Systemadmin)
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
| `ROI_PUBLIC_URL` | `http://localhost:8090` | öffentliche Adresse, z. B. `https://mediator.example.com` |
| `ROI_IMAGE` | `rtl-over-internet:latest` | nur `docker-compose.yml`: Image; ohne Registry wird es lokal gebaut |
| `ROI_DATA_PATH` | `./data` | nur `docker-compose.yml`: Datenverzeichnis auf dem Host (UID 10001) |
| `ROI_AUTH_MODES` | `all` | `all` (Passwort + OIDC), `internal` (nur Passwort), `oidc` (nur OIDC, kein Admin-Passwort nötig) |
| `ROI_OIDC_ISSUER`, `ROI_OIDC_CLIENT_ID`, `ROI_OIDC_CLIENT_SECRET` | leer | OpenID Connect (z. B. authentik, Keycloak). Redirect-URI: `<ROI_PUBLIC_URL>/login/oidc/callback` |
| `ROI_OIDC_ADMIN_GROUPS` / `ROI_OIDC_USER_GROUPS` | leer | Gruppen aus dem Claim `groups`: Systemadmin bzw. Benutzer ohne Rechte (bis ihm Instanzen zugewiesen werden). Mindestens eine Pflicht, sobald OIDC konfiguriert ist |
| `ROI_OIDC_BUTTON_LABEL` | `Mit SSO anmelden` | Text des Buttons |
| `ROI_TRUSTED_PROXIES` | leer | IPs/Netze, von denen `X-Forwarded-For` übernommen wird (nginx) |
| `ROI_SECRET_KEY` | erzeugt | Schlüssel für CSRF-Tokens (mind. 32 Zeichen). Fehlt er, wird er in `/data/secret_key` angelegt. |
| `ROI_COOKIE_SECURE` | aus URL | `Secure`-Cookie; Standard: an bei `https://`-URL, sonst aus (lokaler Test) |
| `ROI_HTTP_HOST` / `ROI_HTTP_PORT` | `127.0.0.1` / `8090` | Adresse der Weboberfläche |
| `ROI_RENDEZVOUS_BIND` | `::` | Adresse für UDP (`::` = IPv4 und IPv6) |
| `ROI_RENDEZVOUS_PORTS` | `3478,3479` | genau zwei UDP-Ports (NAT-Erkennung) |
| `ROI_RENDEZVOUS_HOST` | Host aus URL | Hostname, den die Server für das Rendezvous nutzen |
| `ROI_DATA_DIR` | `/data` | SQLite-Datenbank und Schlüssel |
| `ROI_TIMEZONE` | `Europe/Vienna` | Zeitzone der Anzeige |

## Installation auf einem Server

Kurz: DNS-Name, Firewall für TCP 80/443 und **UDP 3478–3479**, `.env` aus `.env.example`,
`docker compose up -d --build`, nginx davor ([docs/nginx.conf.example](docs/nginx.conf.example)) und
`certbot --nginx`. Schritt für Schritt: [docs/deployment.md](docs/deployment.md).

- Releases und Images für eine eigene Registry: [docs/release.md](docs/release.md)
- Testablauf: [docs/testing.md](docs/testing.md)

## Lokaler Test

Nativ (empfohlen, damit reflexive Adressen stimmen), Python 3.11 oder neuer:

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements-dev.txt
$env:ROI_DATA_DIR = ".\data"
$env:ROI_ADMIN_USER = "admin"
$env:ROI_ADMIN_PASSWORD = "mindestens-12-zeichen"
$env:ROI_PUBLIC_URL = "http://<LAN-IP>:8090"   # LAN-Adresse dieses Rechners
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
