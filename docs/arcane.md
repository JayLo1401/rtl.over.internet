# Betrieb mit Arcane (Hetzner, rtl.jaycloud.at)

Arcane verwaltet den Container als Compose-Projekt. nginx, Zertifikat und Firewall bleiben auf dem Host.

## Voraussetzungen

1. **Image in der Registry:** Der Release-Workflow hat mindestens ein Release gebaut
   (`repository.jaycloud.at/rtl.over.internet/rtl-over-internet:<version>`), siehe [release.md](release.md).
2. **Datenverzeichnis auf dem Host** (der Container läuft als UID 10001):
   ```sh
   mkdir -p /opt/rtl.over.internet/data
   chown 10001:10001 /opt/rtl.over.internet/data && chmod 700 /opt/rtl.over.internet/data
   ```
3. **Firewall:** TCP 80/443 und **UDP 3478–3479** eingehend (Hetzner Cloud Firewall und ggf. `ufw allow 3478:3479/udp`).
4. **DNS:** `rtl.jaycloud.at` (A und AAAA) auf den Server.
5. **nginx + Zertifikat** auf dem Host: [nginx-rtl.jaycloud.at.conf](nginx-rtl.jaycloud.at.conf), dann
   `certbot certonly --webroot -w /var/www/certbot -d rtl.jaycloud.at` und `nginx -t && systemctl reload nginx`.

## In Arcane

1. **Registry hinterlegen** (nur, wenn das Nexus-Repository keinen anonymen Pull erlaubt):
   Einstellungen → Container-Registries → `repository.jaycloud.at` mit einem Nexus-Lese-Benutzer.
2. **Neues Projekt** `rtl-over-internet`:
   - Compose: Inhalt von [`docker-compose.yml`](../docker-compose.yml) aus diesem Repo
   - Umgebung (.env): Vorlage [`.env.example`](../.env.example), mindestens
     ```env
     ROI_PUBLIC_URL=https://rtl.jaycloud.at
     ROI_ADMIN_USER=admin
     ROI_ADMIN_PASSWORD=<openssl rand -base64 24>
     ROI_DATA_PATH=/opt/rtl.over.internet/data
     ```
     optional die `ROI_OIDC_*`-Werte für authentik (Redirect-URI `https://rtl.jaycloud.at/login/oidc/callback`).
3. **Deploy.** Im Log müssen erscheinen: `Rendezvous lauscht auf UDP :::3478` und `:::3479` sowie
   `Uvicorn running on http://127.0.0.1:8090`.

`network_mode: host` bleibt Pflicht: Nur so sieht der Rendezvous-Endpunkt die echten Absenderadressen.
Deshalb gibt es im Projekt keine Port-Freigaben; die Weboberfläche ist nur über nginx erreichbar.

## Prüfen

```sh
curl -sI https://rtl.jaycloud.at/healthz          # 204
ss -ulpn | grep -E ':347[89]'                      # beide UDP-Ports offen
```

Danach in den rtltcp.server die Instanz mit `https://rtl.jaycloud.at` hinzufügen.

## Update

In Arcane „Pull & Redeploy“ (bei `ROI_TAG=latest`) oder `ROI_TAG` auf die neue Version setzen und neu deployen.
Die Datenbank in `ROI_DATA_PATH` bleibt erhalten. Backup: dieses Verzeichnis.
