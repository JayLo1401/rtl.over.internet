# Schnittstelle rtl.over.internet ↔ rtltcp.server

Status: **Entwurf 5** · Gegenstück: `rtltcp.server` (Anbieter = Standort 1, Nutzer = Standort 2)

Entwurf 5: Zugangsdatei (JSON) zum Hochladen beim Einrichten (§1.1). Das Protokoll selbst ist unverändert.

Entwurf 4: optionale Felder `location` (Standort) und `antenna` (Antennentyp) pro Freigabe in `announce` und
`shares` (§2.2, §2.3). Abwärtskompatibel, ältere Server senden sie nicht bzw. ignorieren sie.

Entwurf 3: Enrollment nur noch mit Instanz-Code und Passwort, ohne Benutzer (§1).

Änderungen gegenüber Entwurf 1: Byte-Layout der Rendezvous-Pakete korrigiert (§3, vorher 63 bzw. 65 Byte),
Byte-Reihenfolge festgelegt, `provider_code` bei `REJECTED`, Regeln für `error`/`revoke`, Grenzen und
Zeitlimits ergänzt (§2.6).

rtl.over.internet ist nur für Anmeldung, Berechtigung und Verbindungsaufbau zuständig. Der Stream läuft
**direkt** zwischen den Standorten (QUIC über UDP, Hole-Punching) und **nie** über diesen Dienst, auch nicht als
Fallback.

```
rtltcp.server ──HTTPS──▶ POST /api/v1/enroll               (einmalig: Code + Passwort → Geräte-Token)
rtltcp.server ──WSS────▶ /api/v1/control                   (dauerhaft, ausgehend, Bearer-Token)
rtltcp.server ──UDP────▶ :3478 / :3479  Rendezvous         (nur während des Verbindungsaufbaus)
rtltcp.server ◀═QUIC═══▶ rtltcp.server                     (direkt, Stream)
```

## 1. Anmeldung (Enrollment)

```
POST /api/v1/enroll
{ "instance_code": "K7QM-4XPD", "password": "…",
  "server_id": "<uuid, fest pro rtltcp.server>", "server_name": "Dachboden", "version": "1.3.0" }

200 { "device_token": "<geheim>", "device_id": 12, "instance": { "id": 3, "name": "Funkfreund Max" } }
401 { "error": "INVALID_CREDENTIALS" }      Code oder Passwort falsch (immer dieselbe Antwort)
403 { "error": "INSTANCE_DISABLED" }
429 { "error": "RATE_LIMITED", "retry_after": 600 }
```

- `instance_code`: Groß- und Kleinschreibung egal, Bindestrich optional.
- `password`: das Passwort **der Instanz** (beim Anlegen erzeugt) oder das Admin-Passwort von rtl.over.internet.
- Es gibt **keinen Benutzer** mehr (Entwurf 3). Ein mitgeschicktes `user` wird ignoriert, damit ältere
  rtltcp.server (1.5.0) weiter funktionieren.

### 1.1 Zugangsdatei (Entwurf 5)

In der Weboberfläche von rtl.over.internet lädt man pro Instanz eine Zugangsdatei herunter
(`rtl-over-internet-<name>.json`). Der rtltcp.server nimmt sie bei „Instanz hinzufügen“ als Upload an
und füllt damit Server-URL, Instanz-Code und Passwort aus, sodass nichts abgeschrieben werden muss.

```json
{
  "format": "rtl.over.internet/credentials",
  "version": 1,
  "server": "https://rtl.jaycloud.at",
  "instance_code": "K7QM-4XPD",
  "password": "…",
  "instance": { "id": 3, "name": "Funkfreund Max" },
  "created_at": "2026-11-10T07:30:00+00:00"
}
```

- Der rtltcp.server prüft `format` und `version` (nur `1` bekannt; unbekannte Felder ignorieren).
- `server` ist die Basis-URL für Enrollment (`<server>/api/v1/enroll`) und Steuerkanal
  (`<server>` mit `https` → `wss`, `/api/v1/control`).
- Danach normal mit `instance_code` und `password` das Enrollment ausführen. Wie bei der Eingabe von Hand
  wird nur das Geräte-Token gespeichert, **nicht die Datei und nicht das Passwort**.
- Die Datei enthält das Passwort im Klartext. Wer sie hat, kann einen Server an der Instanz anmelden.
- Der rtltcp.server speichert **nur das Token**. Es gilt pro Server und Instanz. Eine erneute Anmeldung
  desselben `server_id` bei derselben Instanz ersetzt das alte Token.
- Das Token ist in der Weboberfläche widerrufbar. Danach antwortet der Steuerkanal mit Close-Code `4401`.

## 2. Steuerkanal

`wss://rtl.jaycloud.at/api/v1/control`, Header `Authorization: Bearer <device_token>`.
Eine Verbindung pro Token (also pro Instanz). Alle Nachrichten sind JSON-Textframes mit `"type"`, max. 64 KiB.
Unbekannte Felder und Typen werden ignoriert. WebSocket-Ping alle 20 s. Bei Abbruch neu verbinden mit Backoff
(1 s, 2 s, 4 s … max. 60 s).

Close-Codes: `4401` Token ungültig/widerrufen (nicht wiederholen), `4403` Instanz deaktiviert (nach 5 min
wieder versuchen), `4409` dieselbe Anmeldung hat sich erneut verbunden (die alte Verbindung wird geschlossen),
`1008` Protokollverstoß (kein/ungültiges `hello` innerhalb von 10 s, kein JSON, zu groß, mehr als 100 Nachrichten
in 10 s), `1000` vom Admin getrennt, `1012` Vermittler startet neu. Bei `1008`, `1000` und `1012` normal mit
Backoff neu verbinden.

Auch bei ungültigem Token wird der WebSocket zuerst angenommen und dann mit `4401` geschlossen (kein HTTP-Fehler
beim Upgrade), damit der Client den Grund sicher erkennt.

### 2.1 Anmeldung am Kanal

```
S → V  { "type": "hello", "server_name": "Dachboden", "version": "1.3.0", "cert_fp": "AB:CD:…" }
V → S  { "type": "welcome", "device_id": 12, "instance": { "id": 3, "name": "Funkfreund Max" },
         "rendezvous": [ { "host": "rtl.jaycloud.at", "port": 3478 }, { "host": "rtl.jaycloud.at", "port": 3479 } ] }
V → S  { "type": "shares", … }      (siehe 2.3)
```

`cert_fp` ist der SHA-256-Fingerprint des eigenen QUIC-Zertifikats (selbst erzeugt). Der Vermittler gibt ihn nur
an die Gegenstelle einer genehmigten Sitzung weiter, und zwar **unverändert** so, wie er im `hello` kam. Erlaubt
sind `AB:CD:…` (32 Hex-Paare mit Doppelpunkt) oder 64 Hex-Zeichen ohne Trenner; Groß-/Kleinschreibung beim
Vergleich ignorieren. `server_name` aus dem `hello` ersetzt den Namen aus dem Enrollment.

### 2.2 Anbieter: Freigaben

```
S → V  { "type": "announce", "shares": [
           { "stick_id": "00000001", "name": "Standort1 Stick 1", "tuner": "R828D",
             "state": "ready", "compression": false,
             "location": "Wien Dach", "antenna": "DAB-Rundstrahler" } ] }
```

`location` und `antenna` sind optional (Freitext, wie im rtltcp.server pro Gerät eingetragen). Sie entsprechen
`server_info.device.location` und `server_info.device.antenna` in rtl_tcp Jay extended. Bis 200 Zeichen werden
angenommen, gespeichert und weitergegeben werden höchstens 100 druckbare Zeichen. Fehlen sie, gilt `""`.

Immer die vollständige Liste. Erneut senden, sobald sich etwas ändert (Name, Zustand, Freigabe). `state` wie
in Jay extended (`ready`, `idle`, `device_not_ready`, `device_lost`, `busy`). Grenzen: max. 64 Freigaben,
`stick_id` 1–64 druckbare ASCII-Zeichen ohne Leerzeichen, `name` max. 100, `tuner` und `state` max. 32 Zeichen,
`location` und `antenna` siehe oben.
Der Vermittler speichert den letzten Stand, eine leere Liste entfernt alle Freigaben des Anbieters.

### 2.3 Nutzer: verfügbare Sticks

```
V → S  { "type": "shares", "shares": [
           { "share_id": "12:00000001", "provider": { "device_id": 12, "name": "Dachboden" },
             "stick_id": "00000001", "name": "Standort1 Stick 1", "tuner": "R828D",
             "state": "ready", "online": true, "compression": false,
             "location": "Wien Dach", "antenna": "DAB-Rundstrahler" } ] }
```

`location` und `antenna` kommen unverändert vom Anbieter (immer vorhanden, ggf. `""`). Der Nutzer-Server gibt sie
für den entfernten Stick lokal als `server_info.device.location`/`antenna` an seine Clients (home.radio) weiter.

Alle Freigaben der Instanz (auch die eigenen, mit `provider.device_id` = eigene ID). Wird bei jeder Änderung neu
gesendet. Ein Anbieter, der offline geht, bleibt mit `online: false` in der Liste.

### 2.4 Sitzung öffnen

```
1  Nutzer   → V   { "type": "open_stream", "req": "a1", "share_id": "12:00000001" }
2  V → Anbieter   { "type": "stream_request", "session": "<id>", "stick_id": "00000001",
                    "from": { "device_id": 15, "name": "Wohnzimmer" } }
3  Anbieter → V   { "type": "stream_accept", "session": "<id>" }
               or { "type": "stream_reject", "session": "<id>", "code": "BUSY", "message": "in use by 192.168.1.20" }
4  V → beide      { "type": "session", "session": "<id>", "req": "a1" (nur Nutzer), "role": "server" | "client",
                    "punch_key": "<base64, 32 Byte>", "peer": { "device_id": …, "name": …, "cert_fp": "…" },
                    "lease": 60 }
5  beide → V      { "type": "candidates", "session": "<id>", "candidates": [ "[2a02:…]:51234", "192.168.1.5:51234",
                    "84.115.1.2:40211" ], "nat": "endpoint_independent" | "symmetric" | "none" | "unknown" }
6  V → beide      { "type": "punch", "session": "<id>", "peer_candidates": [ … ], "peer_nat": "…",
                    "start_at": 1767225600123 }      (Unix-Zeit in ms, ca. 500 ms in der Zukunft)
7  beide → V      { "type": "punch_result", "session": "<id>", "ok": true, "path": "[2a02:…]:51234" }
8  beide → V      { "type": "stream_end", "session": "<id>", "bytes": 123456789, "reason": "client left" }
```

- `role: server` = Anbieter (QUIC-Server), `client` = Nutzer (QUIC-Client).
- `session` ist eine UUID in der üblichen Textform (`xxxxxxxx-xxxx-…`), `punch_key` 32 Byte Standard-Base64.
- Fehler auf `open_stream`: `{ "type": "error", "req": "a1", "code": "…", "message": "…" }` mit
  `NOT_FOUND` (auch: eigene Freigabe), `PEER_OFFLINE`, `INSTANCE_DISABLED`, `LIMIT_REACHED`, `REJECTED`,
  `TIMEOUT` (Anbieter antwortet nicht in 10 s / Kandidaten fehlen 10 s nach `session`).
- `REJECTED` trägt den Code des Anbieters zusätzlich in `provider_code`:
  `{ "type": "error", "req": "a1", "session": "<id>", "code": "REJECTED", "provider_code": "BUSY", "message": "in use by 192.168.1.20" }`
- Melden beide `ok: false` (oder meldet 15 s nach `start_at` keine Seite `ok: true`), schickt der Vermittler
  `{ "type": "error", "session": …, "code": "DIRECT_CONNECTION_FAILED", "message": "…", "nat": { "server": "…",
  "client": "…" } }` an beide, mit einem Hinweis (z. B. „IPv6 am Router aktivieren“). Meldet eine Seite
  `ok: true`, gilt die Sitzung als verbunden.
- `candidates`: max. 16 Einträge, nur IP-Literale: `[IPv6]:port` oder `a.b.c.d:port` (keine Hostnamen).
  `nat` außerhalb der vier Werte wird als `unknown` behandelt. `candidates` wird pro Seite einmal gesendet.
- `stream_end` beendet die Sitzung. Die Gegenseite bekommt `revoke` mit `reason: "peer_ended"`. Die Gegenseite
  darf danach (bis 2 min) trotzdem noch ihr eigenes `stream_end` mit `bytes` schicken, es wird nur noch verbucht.

### 2.6 Regeln für `error` und `revoke`

- Ein `error` mit `req` gehört zu einer Anfrage, ein `error` mit `session` **beendet** diese Sitzung (danach
  kommt kein `revoke` mehr). An den Nutzer gehen Sitzungsfehler immer mit `req` **und** `session`.
- `BAD_REQUEST`: Nachricht mit ungültigen Feldern, die Verbindung bleibt bestehen. Enthält `req`/`session` der
  auslösenden Nachricht, falls vorhanden.
- `revoke.reason`: `peer_ended`, `peer_offline`, `timeout` (an den Anbieter, wenn er nicht rechtzeitig
  angenommen hat), `instance_disabled`, `instance_deleted`, `token_revoked`, `token_replaced`,
  `disconnected_by_admin`, `ended_by_admin`, `shutdown`. Unbekannte Gründe wie `revoke` behandeln.
- Ein Nutzer darf höchstens 8 nicht verbundene Sitzungen gleichzeitig offen haben (sonst `LIMIT_REACHED`).
  Zusätzlich kann der Admin pro Instanz die gleichzeitigen Sitzungen begrenzen.

### 2.5 Lease und Widerruf

- Für jede angenommene Sitzung schickt der Vermittler alle 20 s an beide Seiten
  `{ "type": "lease", "session": "<id>", "ttl": 60 }`. Ohne Verlängerung innerhalb von `ttl` Sekunden beenden die
  Server den Stream selbst.
- `{ "type": "revoke", "session": "<id>", "reason": "…" }`: Stream sofort beenden (Instanz deaktiviert, Token
  widerrufen, Admin hat die Sitzung beendet, Gegenstelle offline).

## 3. Rendezvous-Endpunkt (UDP)

UDP 3478 und 3479 (zwei Ports, um das NAT-Verhalten zu erkennen), am Reverse-Proxy vorbei direkt vom Container.
Nur Pakete einer laufenden Sitzung werden beantwortet. Die Antwort ist nie größer als die Anfrage.

Anfrage (64 Byte):

```
Offset  Länge  Inhalt
 0      4      "ROI1" (ASCII)
 4      1      type = 1
 5      16     session (UUID-Bytes, RFC 4122, big-endian)
21      8      nonce (zufällig)
29      19     0x00
48      16     mac = HMAC-SHA256(punch_key, Byte 0..47)[0..15]
```

Antwort (64 Byte):

```
Offset  Länge  Inhalt
 0      4      "ROI1"
 4      1      type = 2
 5      16     session
21      8      nonce (Echo)
29      1      family: 4 oder 6
30      2      port (big-endian)
32      16     addr (IPv4 als ::ffff:a.b.c.d)
48      16     mac = HMAC-SHA256(punch_key, Byte 0..47)[0..15]
```

Alle Mehrbyte-Zahlen in Netzwerk-Byte-Reihenfolge. **Achtung .NET:** `Guid.ToByteArray()` liefert die ersten drei
Felder little-endian. Für die UUID-Bytes `guid.TryWriteBytes(span, bigEndian: true, out _)` (ab .NET 8)
bzw. `new Guid(bytes, bigEndian: true)` verwenden.

Der Client muss die MAC der Antwort prüfen. Der Endpunkt antwortet nur, solange die Sitzung zwischen `session`
und ihrem Ende ist, und höchstens 200-mal pro Sitzung. Ungültige Pakete werden stumm verworfen.

**NAT-Typ:** Der rtltcp.server fragt denselben lokalen Socket an beiden Ports an. Gleiche reflexive Adresse:
`endpoint_independent`. Verschieden: `symmetric`. Reflexive gleich lokaler Adresse: `none` (öffentliche IP).

## 4. Direkte Verbindung (zwischen den rtltcp.server)

1. Beide binden **einen** UDP-Socket (Dual-Stack) für die Sitzung und sammeln Kandidaten: öffentliche IPv6-Adressen
   zuerst, LAN-Adressen, reflexive IPv4 aus §3.
2. Ab `start_at` senden beide alle 50 ms Punch-Pakete an alle Kandidaten der Gegenseite, max. 5 s:
   ```
   "ROIP"  u8 type (1 = probe, 2 = ack)  u8[16] session  u8[8] nonce  u8[16] mac   (HMAC wie oben, über Byte 0..28)
   ```
   45 Byte, MAC an Offset 29. Dieses Paket sieht der Vermittler nie, es ist hier nur zur Vollständigkeit.
   Pakete mit falscher Sitzung bzw. MAC werden verworfen. Ein `probe` wird mit `ack` beantwortet. Wer ein `ack`
   bekommt, hat einen Weg. Das erste Paar in beide Richtungen gewinnt, IPv6 bevorzugt.
3. Auf genau diesem lokalen Port startet **QUIC** (ALPN `rtltcp-jay/1`): `server` lauscht, `client` verbindet sich
   von seinem Port aus zum gewonnenen Kandidaten. Beide prüfen das Zertifikat der Gegenseite gegen `peer.cert_fp`.
4. Pro Stick ein bidirektionaler QUIC-Stream: Präambel `u8 Länge | stick_id (UTF-8)`, danach rtl_tcp Jay extended
   (siehe rtltcp.server `docs/protocol-v2.md`). Keepalive 15 s.
5. Fällt die Verbindung weg, baut der Nutzer eine neue Sitzung über den Vermittler auf.

Es gibt **kein Relay**. Scheitert Schritt 2, ist die Sitzung mit `DIRECT_CONNECTION_FAILED` beendet.
