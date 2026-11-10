# Release und Image in einer eigenen Registry

Jeder Push auf `main` (außer reine Doku-Änderungen) baut über `.github/workflows/release.yml` ein Release:

1. Version aus den Commits seit dem letzten Release:
   `feat:` → Minor, `fix:` und alles andere → Patch, `feat!:`/`BREAKING CHANGE`/`[major]` → Major.
   Das erste Release nimmt `__version__` aus `app/__init__.py`.
2. `pytest` und `pip-audit`
3. Image für `linux/amd64` und `linux/arm64`, Rauchtest des amd64-Images (Start, `/healthz`, Enrollment → 401)
4. Push nach `<Registry-Host>/<NEXUS_REPO>/rtl-over-internet:<version>` und `:latest`
5. Tag `v<version>` und GitHub-Release mit Notizen

Schlägt ein Schritt fehl, gibt es keinen Tag. Der nächste Push baut dieselbe Version neu.

Ohne Registry braucht man den Workflow nicht: `docker compose up -d --build` baut das Image direkt auf dem Server.

## GitHub-Einstellungen

Der Workflow ist auf eine Docker-Registry in Sonatype Nexus ausgelegt, funktioniert aber mit jeder Registry,
deren Images `<Host>/<Repository>/<Image>` heißen.

| Art | Name | Wert |
|---|---|---|
| Secret | `NEXUS_USER` | Benutzer mit Push-Recht auf das Repository |
| Secret | `NEXUS_PASS` | dessen Passwort |
| Variable | `NEXUS_URL` | z. B. `https://registry.example.com` (der Host ist die Registry) |
| Variable | `NEXUS_REPO` | Name des Docker-hosted-Repositorys; Image = `<Host>/<NEXUS_REPO>/rtl-over-internet` |

## Nexus einrichten

1. **Docker-hosted-Repository** anlegen.
2. **Docker-Routing am Host.** Docker-Clients sprechen eine Registry immer unter `https://<host>/v2/` an.
   **Variante A, Path-Based-Routing (passt zu den Variablen oben):** Im Nexus „Use path-based routing“ für
   Docker aktivieren. Dann heißen Images `<host>/<Repository>/<Image>`.
   **Variante B, eigener Port:** Beim Repository einen HTTP-Connector setzen (z. B. 8085) und in nginx einen
   eigenen Host davor, z. B. `docker.example.com` → `127.0.0.1:8085`. Dann muss der Image-Name im Workflow
   (ohne `<NEXUS_REPO>/`) angepasst werden.
3. **Security → Realms:** „Docker Bearer Token Realm“ aktivieren (ohne den lehnt Nexus `docker login` ab).
4. **Rechte:** Rolle mit `nx-repository-view-docker-<Repository>-*` (bzw. `-add`, `-edit`, `-read`, `-browse`)
   für den Runner-Benutzer. Für den Server entweder einen Lese-Benutzer (`docker login` einmalig) oder beim
   Repository „Allow anonymous docker pull“ einschalten.
5. **nginx vor dem Nexus:** große Uploads erlauben, sonst brechen Layer-Pushes ab:
   ```nginx
   client_max_body_size 0;
   proxy_request_buffering off;
   proxy_read_timeout 600s;
   ```

**Prüfen** (muss 401 mit `WWW-Authenticate: Bearer …` liefern, nicht 404):

```sh
curl -sI https://registry.example.com/v2/
docker login registry.example.com
docker pull registry.example.com/<Repository>/rtl-over-internet:latest   # nach dem ersten Release
```

Der Release-Workflow prüft `/v2/` als ersten Schritt und bricht mit einem Hinweis ab, solange das Routing fehlt.

## Update auf dem Server

In `.env` `ROI_IMAGE=registry.example.com/<Repository>/rtl-over-internet:<version>` setzen, dann:

```sh
docker compose pull && docker compose up -d
```

Die laufende Version steht unten in der Weboberfläche (nur nach dem Login sichtbar).
