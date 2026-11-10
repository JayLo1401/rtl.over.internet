# Release und Docker-Repository im Nexus

Jeder Push auf `main` (außer reine Doku-Änderungen) baut über `.github/workflows/release.yml` ein Release:

1. Version aus den Commits seit dem letzten Release, gleiches Schema wie bei rtltcp.server:
   `feat:` → Minor, `fix:` und alles andere → Patch, `feat!:`/`BREAKING CHANGE`/`[major]` → Major.
   Das erste Release nimmt `__version__` aus `app/__init__.py` (0.1.0).
2. `pytest` und `pip-audit`
3. Image für `linux/amd64` und `linux/arm64`, Rauchtest des amd64-Images (Start, `/healthz`, Enrollment → 401)
4. Push nach `repository.jaycloud.at/rtl.over.internet/rtl-over-internet:<version>` und `:latest`
5. Tag `v<version>` und GitHub-Release mit Notizen

Schlägt ein Schritt fehl, gibt es keinen Tag. Der nächste Push baut dieselbe Version neu.

## GitHub-Einstellungen

| Art | Name | Wert |
|---|---|---|
| Secret | `NEXUS_USER` | Nexus-Benutzer mit Push-Recht auf `rtl.over.internet` |
| Secret | `NEXUS_PASS` | dessen Passwort |
| Variable | `NEXUS_URL` | `https://repository.jaycloud.at` (der Host ist die Registry) |
| Variable | `NEXUS_REPO` | `rtl.over.internet` (Docker hosted); Image = `<Host>/<NEXUS_REPO>/rtl-over-internet` |

## Nexus einrichten

Das Docker-hosted-Repository `rtl.over.internet` existiert (Nexus 3.98 Community). Damit `docker login` und
`docker push` funktionieren, fehlt noch Folgendes:

1. **Docker-Routing am Host.** Docker-Clients sprechen eine Registry immer unter `https://<host>/v2/` an, nicht
   unter `/repository/<name>/v2/`. Derzeit liefert `https://repository.jaycloud.at/v2/` 404.
   **Variante A, Path-Based-Routing (passt zu den Standardwerten oben):** Im Nexus das Path-Based-Routing für
   Docker aktivieren (in den Docker-Einstellungen bzw. beim Repository unter „Repository Connectors“, je nach
   Version). Dann heißen Images `repository.jaycloud.at/<Repository>/<Image>`.
   **Variante B, eigener Port:** Beim Repository einen HTTP-Connector setzen (z. B. 8085) und in nginx einen
   eigenen Host davor, z. B. `docker.jaycloud.at` → `127.0.0.1:8085`. Dann müssen der Image-Name im Workflow
   (ohne `<NEXUS_REPO>/`) und in `docker-compose.yml` angepasst werden.
2. **Security → Realms:** „Docker Bearer Token Realm“ aktivieren (ohne den lehnt Nexus `docker login` ab).
3. **Rechte:** Rolle mit `nx-repository-view-docker-rtl.over.internet-*` (bzw. `-add`, `-edit`, `-read`, `-browse`)
   für den Runner-Benutzer. Für den Hetzner-Server entweder einen Lese-Benutzer (`docker login` einmalig auf dem
   Server) oder beim Repository „Allow anonymous docker pull“ einschalten.
4. **nginx vor dem Nexus:** große Uploads erlauben, sonst brechen Layer-Pushes ab:
   ```nginx
   client_max_body_size 0;
   proxy_request_buffering off;
   proxy_read_timeout 600s;
   ```

**Prüfen** (muss 401 mit `WWW-Authenticate: Bearer …` liefern, nicht 404):

```sh
curl -sI https://repository.jaycloud.at/v2/
docker login repository.jaycloud.at
docker pull repository.jaycloud.at/rtl.over.internet/rtl-over-internet:latest   # nach dem ersten Release
```

Der Release-Workflow prüft `/v2/` als ersten Schritt und bricht mit einem Hinweis ab, solange das Routing fehlt.

## Update auf dem Server

```sh
cd /srv/rtl.over.internet
docker compose pull && docker compose up -d
```

Feste Version statt `latest`: `ROI_TAG=0.1.0 docker compose up -d`. Die laufende Version steht unten in der
Weboberfläche (nur nach dem Login sichtbar).
