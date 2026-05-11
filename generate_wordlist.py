#!/usr/bin/env python3
"""
Forensic Wordlist Generator – Generisch & RAM-optimiert

Beschreibung:
    Dieses Skript generiert umfassende Passwort-Wordlists für forensische Zwecke
    (z.B. für Hashcat, John the Ripper). Es basiert auf einer benutzerdefinierten
    Input-Datei mit Mustern (Telefonnummern, IDs, Datumsangaben).

    Kernfunktionen:
    1. Liest Muster aus einer Textdatei.
    2. Extrahiert automatisch "atomare" Bausteine (z.B. Vorwahl, Nummer, Datum).
    3. Generiert alle Kombinationen (1- bis n-teilig) mit verschiedenen Trennzeichen.
    4. Wendet typische Suffixe (Jahreszahlen, Sonderzeichen) und Reverse-Varianten an.
    5. Streamt Ergebnisse direkt auf die Festplatte (RAM-optimiert).
    6. Bietet Live-Statusausgaben und Encoding-Fallback.

Version: 1.0.0
Autor: Heiko Rittelmeier mit Lumo
Datum: Mai 2026
Lizenz: MIT (Freie Nutzung für forensische Analysen)
Repository: https://github.com/SirHenryR/FWG
"""

import itertools
import argparse
import sys
import time
import os

# ==============================================================================
# VERSIONSKONSTANTE
# ==============================================================================

VERSION = "1.0.0"
VERSION_DATE = "2026-05-11"

# ==============================================================================
# KONFIGURATION & ARGUMENTE
# ==============================================================================

def parse_arguments():
    """Parsen der Kommandozeilenargumente."""
    parser = argparse.ArgumentParser(
        description=f"Forensic Wordlist Generator v{VERSION} – Generisch mit Input-Datei",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python3 generate_wordlist.py -i muster.txt
  python3 generate_wordlist.py -i muster.txt -l 32 -c 3 -o small_list.txt
  python3 generate_wordlist.py -i muster.txt --no-suffix --no-reverse
        """
    )
    
    parser.add_argument(
        "--version", "-V", 
        action="version", 
        version=f"%(prog)s v{VERSION} ({VERSION_DATE})"
    )
    parser.add_argument(
        "--input", "-i", 
        type=str, 
        required=True, 
        help="Pfad zur Datei mit Basis-Mustern (eine pro Zeile). Kommentare mit # werden ignoriert."
    )
    parser.add_argument(
        "--max-length", "-l", 
        type=int, 
        default=64, 
        help="Maximale Zeichenlänge pro Eintrag (Standard: 64). Kürzere Limits sparen Zeit."
    )
    parser.add_argument(
        "--output", "-o", 
        type=str, 
        default="forensic_wordlist_raw.txt", 
        help="Name der Ausgabedatei (Standard: forensic_wordlist_raw.txt)."
    )
    parser.add_argument(
        "--chain-max", "-c", 
        type=int, 
        default=4, 
        help="Maximale Anzahl kombinierter Elemente (Standard: 4). Erhöht die Kombinatorik exponentiell."
    )
    parser.add_argument(
        "--quiet", "-q", 
        action="store_true", 
        help="Deaktiviert alle Statusausgaben außer Fehlermeldungen."
    )
    parser.add_argument(
        "--no-reverse", 
        action="store_true", 
        help="Deaktiviert die Generierung von Reverse-Varianten (z.B. 'abc' -> 'cba')."
    )
    parser.add_argument(
        "--no-suffix", 
        action="store_true", 
        help="Deaktiviert die Anhängung von Suffixen (z.B. '123', '!')."
    )

    return parser.parse_args()

# ==============================================================================
# KONSTANTEN & STANDARDWERTE
# ==============================================================================

# Trennzeichen, an denen Input-Zeilen automatisch zerlegt werden (Atomic Extraction)
# Enthält gängige Trenner in Telefonnummern, IDs und Datumsangaben.
EXTRACT_SEPARATORS = [' ', '/', '-', '_', '.', '+']

# Trennzeichen, die bei der Kombination von Elementen verwendet werden
SEPARATORS = ["", " ", "/", "-", "_", "."]

# Standard-Suffixe (Jahreszahlen, kleine Zahlen, Sonderzeichen)
DEFAULT_SUFFIXES = ["", "1", "12", "123", "1234", "!", "!!", "!1", "01", "69", "99", "00"]

# Interval für Statusausgaben (Anzahl Einträge)
REPORT_INTERVAL = 1_000_000

# ==============================================================================
# HILFSFUNKTIONEN
# ==============================================================================

def load_input_file(filepath):
    """
    Liest die Input-Datei mit Encoding-Fallback.
    
    Returns:
        tuple: (original_entries: list, atomic_elements: set)
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Input-Datei '{filepath}' nicht gefunden.")

    encodings = ['utf-8', 'latin-1', 'cp1252']
    lines = []
    used_encoding = None

    for enc in encodings:
        try:
            with open(filepath, "r", encoding=enc) as f:
                lines = f.readlines()
            used_encoding = enc
            break
        except UnicodeDecodeError:
            continue
    
    if not used_encoding:
        raise ValueError(f"Konnte '{filepath}' mit keinem unterstützten Encoding lesen.")

    original_entries = []
    atomic_elements = set()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        original_entries.append(line)
        
        # Automatische Zerlegung in atomare Teile
        parts = [line]
        for sep in EXTRACT_SEPARATORS:
            new_parts = []
            for part in parts:
                new_parts.extend(part.split(sep))
            parts = new_parts
        
        for part in parts:
            p_clean = part.strip()
            if p_clean:
                atomic_elements.add(p_clean)

    return original_entries, sorted(list(atomic_elements))

def stream_chains(base_elements, separators, max_chain, max_length):
    """
    Generator-Funktion zur effizienten Erzeugung von Ketten.
    Nutzt itertools.product für lazy Evaluation (kein RAM-Verbrauch für alle Kombinationen).
    
    Yields:
        str: Ein einzelner Passwort-Kandidat.
    """
    # Vorbereitung: Alle (Trenner, Element)-Paare
    pairs = [(sep, elem) for sep in separators for elem in base_elements]

    for chain_len in range(1, max_chain + 1):
        if chain_len == 1:
            # Einzelne Elemente direkt yielden
            for elem in base_elements:
                if len(elem) <= max_length:
                    yield elem
        else:
            remaining = chain_len - 1
            for first in base_elements:
                # Produkt aller möglichen Kombinationen für die restlichen Positionen
                for combo in itertools.product(pairs, repeat=remaining):
                    result = first
                    for sep, elem in combo:
                        result += sep + elem
                    
                    if len(result) <= max_length:
                        yield result

# ==============================================================================
# HAUPTLOGIK
# ==============================================================================

def main():
    args = parse_arguments()
    
    # Konfiguration aus Argumenten ableiten
    input_file = args.input
    output_file = args.output
    max_length = args.max_length
    max_chain = ar
