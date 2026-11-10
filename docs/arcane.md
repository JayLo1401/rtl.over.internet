# Betrieb mit Arcane (Hetzner, rtl.jaycloud.at)

Arcane verwaltet den Container als Compose-Projekt. nginx, Zertifikat und Firewall bleiben auf dem Host.
Fertige Dateien: [`deploy/docker-compose.arcane.yml`](../deploy/docker-compose.arcane.yml) und
[`deploy/arcane.env.example`](../deploy/arcane.env.example). Daten liegen unter `/srv/rtl.over.internet/data`.

## 1. Host vorbereiten

```sh
mkdir -p /srv/rtl.over.internet/data
chown 10001:10001 /srv/rtl.over.internet/data      # der Container läuft als UID 10001
chmod 700 /srv/rtl.over.internet/data
ufw allow 3478:3479/udp                             # nur falls ufw aktiv ist
```

Hetzner Cloud Console → Firewalls: eingehend **UDP 3478–3479** (TCP 80/443 für nginx).
DNS `rtl.jaycloud.at` (A + AAAA) muss auf den Server zeigen.

## 2. nginx + Zertifikat

Die Konfiguration enthält zunächst nur HTTP; `certbot --nginx` ergänzt TLS und die Umleitung selbst:

```sh
curl -o /etc/nginx/sites-available/rtl.jaycloud.at \
  https://raw.githubusercontent.com/JayLo1401/rtl.over.internet/main/docs/nginx-rtl.jaycloud.at.conf
ln -s /etc/nginx/sites-available/rtl.jaycloud.at /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
certbot --nginx -d rtl.jaycloud.at        # bei der Frage nach Umleitung: Redirect
```

## 3. Arcane

Das Image `repository.jaycloud.at/rtl.over.internet/rtl-over-internet` ist anonym abrufbar, eine Registry
muss in Arcane nicht hinterlegt werden.

1. **Projects → New Project**, Name `rtl-over-internet`
2. **Compose:** Inhalt von
   `https://raw.githubusercontent.com/JayLo1401/rtl.over.internet/main/deploy/docker-compose.arcane.yml`
3. **Environment:** Vorlage `deploy/arcane.env.example`, mindestens
   ```env
   ROI_TAG=0.2.0
   ROI_ADMIN_PASSWORD=<openssl rand -base64 24>
   ROI_SECRET_KEY=<openssl rand -base64 48>
   ```
   `ROI_SECRET_KEY` einmal setzen und nie ändern (damit sind die Instanz-Passwörter verschlüsselt).
   Optional die `ROI_OIDC_*`-Werte für authentik, Redirect-URI `https://rtl.jaycloud.at/login/oidc/callback`.
4. **Deploy.** Im Log müssen erscheinen:
   ```text
   Rendezvous lauscht auf UDP :::3478
   Rendezvous lauscht auf UDP :::3479
   Uvicorn running on http://127.0.0.1:8090
   ```

## 4. Prüfen

```sh
curl -sI https://rtl.jaycloud.at/healthz          # 204
ss -ulpn | grep -E ':347[89]'                      # beide UDP-Ports offen
```

Danach als `admin` anmelden, Instanz anlegen, „Zugangsdatei herunterladen“ und die Datei im rtltcp.server
bei „Instanz hinzufügen“ hochladen.

## Update und Backup

- Update: `ROI_TAG` auf die neue Version setzen und neu deployen (bei `latest`: „Pull & Redeploy“).
- Backup: `/srv/rtl.over.internet/data` (SQLite-Datenbank) und die Umgebung des Arcane-Projekts
  (`ROI_SECRET_KEY`!).
