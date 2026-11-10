# Installation auf einem Server

Der Vermittler läuft als Docker-Container auf einem Server mit öffentlicher IPv4- und möglichst auch IPv6-Adresse.
nginx davor übernimmt TLS. Im Beispiel heißt der Host `mediator.example.com`, Daten liegen unter
`/srv/rtl-over-internet`.

Voraussetzungen: Docker mit Compose-Plugin, nginx, certbot (mit nginx-Plugin), ein DNS-Name.

## 1. DNS und Firewall

- DNS: `A`- und `AAAA`-Eintrag für `mediator.example.com` auf den Server
- Firewall eingehend (Firewall des Hosters **und** ggf. `ufw`):
  - TCP 80 und 443 (nginx)
  - **UDP 3478 und 3479** (Rendezvous, geht direkt an den Container, nicht über nginx)

```sh
ufw allow 80,443/tcp
ufw allow 3478:3479/udp
```

## 2. Dateien und Konfiguration

```sh
git clone https://github.com/<owner>/rtl.over.internet.git /srv/rtl-over-internet
cd /srv/rtl-over-internet
cp .env.example .env
chmod 600 .env
mkdir -p data && chown 10001:10001 data && chmod 700 data    # der Container läuft als UID 10001
```

In `.env` mindestens setzen:

```env
ROI_PUBLIC_URL=https://mediator.example.com
ROI_ADMIN_PASSWORD=<openssl rand -base64 24>
ROI_SECRET_KEY=<openssl rand -base64 48>
```

`ROI_SECRET_KEY` einmal setzen und nie mehr ändern: Damit sind die Instanz-Passwörter verschlüsselt.
Alle weiteren Variablen: [README](../README.md#konfiguration).

## 3. Container starten

```sh
docker compose up -d --build
docker compose logs -f
```

Im Log müssen erscheinen:

```text
Rendezvous lauscht auf UDP :::3478
Rendezvous lauscht auf UDP :::3479
Uvicorn running on http://127.0.0.1:8090
```

`docker-compose.yml` nutzt `network_mode: host`, damit der Rendezvous-Endpunkt die echte Absenderadresse sieht
(kein Docker-Portmapping, kein IPv6→IPv4-Proxy). Die Weboberfläche lauscht dadurch nur auf `127.0.0.1:8090`.

Wer ein fertiges Image aus einer eigenen Registry nutzt (siehe [release.md](release.md)), setzt in `.env`
`ROI_IMAGE=registry.example.com/rtl-over-internet:<version>` und startet mit `docker compose pull && docker compose up -d`.

### Mit einer Compose-Oberfläche (Arcane, Portainer, Dockge …)

Dieselbe `docker-compose.yml` als Projekt anlegen und die Werte aus `.env.example` als Umgebung des Projekts
eintragen. `ROI_IMAGE` auf ein Image aus der Registry setzen (die Oberfläche baut meist nicht selbst) und
`ROI_DATA_PATH` auf einen absoluten Pfad, z. B. `/srv/rtl-over-internet/data` (vorher anlegen, `chown 10001:10001`).

## 4. nginx und Zertifikat

Vorlage: [nginx.conf.example](nginx.conf.example). Darin `mediator.example.com` ersetzen (und den Port, falls
`ROI_HTTP_PORT` geändert wurde). Die Vorlage enthält zunächst nur HTTP; `certbot --nginx` ergänzt TLS und die
Umleitung auf HTTPS selbst.

```sh
cp docs/nginx.conf.example /etc/nginx/sites-available/mediator.example.com
sed -i 's/mediator.example.com/<hostname>/g' /etc/nginx/sites-available/mediator.example.com
ln -s /etc/nginx/sites-available/mediator.example.com /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
certbot --nginx -d <hostname>        # bei der Frage nach Umleitung: Redirect
```

Wichtig in der Konfiguration: WebSocket-Upgrade und `proxy_read_timeout 1h` für `/api/v1/control`, und
`X-Forwarded-For` wird überschrieben statt angehängt (passt zu `ROI_TRUSTED_PROXIES=127.0.0.1/32,::1/128`).
HSTS setzt die App selbst, sobald `ROI_PUBLIC_URL` mit `https://` beginnt.

## 5. Prüfen

```sh
curl -sI https://mediator.example.com/healthz     # 204
ss -ulpn | grep -E ':347[89]'                       # beide UDP-Ports offen
```

Danach unter `https://mediator.example.com` mit `admin` und `ROI_ADMIN_PASSWORD` anmelden, eine Instanz anlegen,
„Zugangsdatei herunterladen“ und die Datei im rtltcp.server bei „Instanz hinzufügen“ hochladen.

## 6. Optional: Anmeldung über OpenID Connect

1. Beim Identity Provider (z. B. authentik, Keycloak) einen confidential OIDC-Client anlegen,
   Redirect-URI `https://mediator.example.com/login/oidc/callback`.
2. Zwei Gruppen anlegen, z. B. `rtl-admins` (Systemadmin) und `rtl-users` (Benutzer), und dafür sorgen, dass
   der Claim `groups` im ID-Token bzw. Userinfo ankommt.
3. In `.env`: `ROI_OIDC_ISSUER`, `ROI_OIDC_CLIENT_ID`, `ROI_OIDC_CLIENT_SECRET`,
   `ROI_OIDC_ADMIN_GROUPS=rtl-admins`, `ROI_OIDC_USER_GROUPS=rtl-users`, dann neu starten.
4. Benutzern nach ihrer ersten Anmeldung Instanzen zuweisen (Seite der Instanz → „Zugewiesene Benutzer“).

## Update und Backup

- Update: `git pull && docker compose up -d --build` bzw. mit Registry-Image `ROI_IMAGE` auf die neue Version
  setzen und `docker compose pull && docker compose up -d`.
- Backup: das Datenverzeichnis (SQLite-Datenbank, ggf. `secret_key`) und `.env` (`ROI_SECRET_KEY`!).
