# Forensic Wordlist Generator

Ein leistungsstarker, RAM-optimierter Generator für Passwort-Wordlists, spezialisiert auf forensische Anwendungen (z.B. für Hashcat, John the Ripper).

Das Skript generiert systematisch alle möglichen Kombinationen aus benutzerdefinierten Mustern (Telefonnummern, IDs, Datumsangaben), inklusive automatischer Zerlegung in atomare Bausteine, Suffixe und Reverse-Varianten.

## Version

**Aktuell: v1.0.0** (2026-05-11)

## Features

- **Generisch & Flexibel:** Liest Muster aus einer beliebigen Textdatei.
- **Automatische Zerlegung:** Extrahiert automatisch atomare Teile (z.B. Vorwahl, Nummer, Datum) aus komplexen Zeilen.
- **Kombinatorik:** Generiert Ketten von 1 bis `N` Elementen mit verschiedenen Trennzeichen.
- **Variationen:** Wendet standardmäßige Suffixe (Jahreszahlen, Sonderzeichen) und Reverse-Varianten an.
- **RAM-optimiert:** Nutzt Streaming und `itertools`, um auch bei Millionen von Einträgen keinen RAM zu verbrauchen.
- **Encoding-Fallback:** Unterstützt UTF-8, Latin-1 und CP1252 automatisch.
- **Live-Status:** Zeigt den Fortschritt und die Generierungsgeschwindigkeit an.
- **Versionskontrolle:** Integrierte Versionsnummerierung für Reproduzierbarkeit.

## Installation

Keine Installation erforderlich. Benötigt wird nur Python 3.6 oder höher.

```bash
chmod +x generate_wordlist.py
