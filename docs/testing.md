# Testablauf

Drei Stufen. Jede baut auf der vorigen auf.

## Stufe 1: automatisch (bei jedem Push)

`python -m pytest`: 49 Tests für Login, Sperre, CSRF, Cookies und Header, Instanzen, Enrollment
(inkl. Rate-Limit und Token-Ersatz), den kompletten Steuerkanal-Ablauf (Annahme, Ablehnung, alle Timeouts,
Fehlercodes, Lease, Revoke, 4401/4403/4409) und das Rendezvous (Paketlayout, HMAC, echte UDP-Sockets auf zwei
Ports). Der Release-Workflow startet zusätzlich das fertige Image und prüft `/healthz` und das Enrollment.

## Stufe 2: lokal im LAN

Aufbau: Vermittler auf Rechner B, **Anbieter** = rtltcp.server auf Rechner A (z. B. Home Assistant,
Stick an Port 1234), **Nutzer** = rtltcp.server und ein SDR-Programm (z. B. home.radio) auf Rechner B.

Vermittler nativ starten (siehe README, „Lokaler Test“), damit die Absenderadressen stimmen. Windows-Firewall:
TCP 8090 und UDP 3478–3479 eingehend erlauben.

| # | Schritt | Erwartet |
|---|---|---|
| 1 | `http://<IP von B>:8090` öffnen, als Admin anmelden, Instanz „Test“ anlegen | Code und Passwort werden angezeigt (auch später auf der Instanzseite) |
| 2 | rtltcp.server auf A: Instanz hinzufügen (Server-URL, Code, Passwort) | Detailseite: Gerät „online“ mit der IP von A und Version |
| 3 | Auf A den Stick der Instanz zuweisen | „Freigegebene Sticks“ zeigt ihn mit Zustand `ready` |
| 4 | rtltcp.server auf B: dieselbe Instanz hinzufügen | sieht den Stick von A, legt einen lokalen Port an |
| 5 | home.radio auf diesen lokalen Port verbinden | Sitzung `requested → accepted → punching → connected`, Weg = LAN-Adresse, Ton/Spektrum laufen |
| 6 | Frequenz und Gain in home.radio ändern | wirkt am Stick wie lokal |
| 7 | home.radio trennen | Sitzung „ended“ mit Dauer und Datenmenge beider Seiten |
| 8 | Während eines Streams: „Beenden“ in der Weboberfläche | Stream bricht sofort ab, Audit-Log `session_ended_by_admin` |
| 9 | Während eines Streams: Instanz deaktivieren | beide Server getrennt (4403), Stream endet; neuer Versuch → `INSTANCE_DISABLED` |
| 10 | Gerät widerrufen | Server getrennt (4401), versucht es **nicht** endlos neu; erneute Anmeldung mit Passwort geht |
| 11 | A neu starten | Gerät offline, Stick beim Nutzer `online: false`, danach automatisch wieder online |
| 12 | Während eines Streams den Vermittler beenden | Stream läuft ohne Lease höchstens 60 s weiter, dann beenden die Server ihn selbst |
| 13 | Stick auf A belegen (anderer Client) und öffnen | Fehler `REJECTED` mit `BUSY` kommt in home.radio an |
| 14 | Zehnmal falsches Passwort bei „Instanz hinzufügen“ | danach `RATE_LIMITED` für 15 min, im Audit-Log sichtbar |

Daneben im Blick behalten: Der Vermittler darf während eines Streams praktisch keinen Traffic haben
(`docker stats` bzw. Task-Manager). Der Stream läuft direkt zwischen den beiden Servern.

Mit Docker Desktop statt nativ funktioniert das alles auch, nur die reflexiven Adressen und der NAT-Typ
sind dann falsch (Docker leitet UDP über einen Proxy).

## Stufe 3: über das Internet

Vermittler auf einem Server wie in [deployment.md](deployment.md). Dann Stufe 2 wiederholen,
aber mit dem Nutzer in einem anderen Netz, z. B. Laptop am Handy-Hotspot oder bei einem Bekannten.

Zusätzlich prüfen:

- `curl -sI https://mediator.example.com/healthz` → 204; Steuerkanal bleibt über Stunden stabil (nginx-Timeout 1 h, Ping alle 20 s)
- NAT-Typ beider Seiten in der Sitzungsliste plausibel (CGNAT im Mobilfunk meist `symmetric` oder `endpoint_independent`)
- Weg der Sitzung: IPv6 bevorzugt; ohne IPv6 auf einer Seite die klare Meldung `DIRECT_CONNECTION_FAILED` mit Hinweis
- 10 min Stream mit ca. 4 MB/s stabil, Traffic auf dem Server nur wenige kB

Die Ergebnisse pro Anschlusskombination gehören in die Testmatrix von Issue #6.
