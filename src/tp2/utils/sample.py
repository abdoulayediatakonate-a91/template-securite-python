import math
from base64 import decode
import magic
from collections import Counter
from urllib.parse import urlsplit
import hashlib
import re
import ipaddress
import lief

class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        i = len(self.data)
        metadata = {"size" : i}
        entropie =  self.shannon_entropy()
        metadata["entropy"] = entropie
        sha256 = hashlib.sha256(self.data).hexdigest()
        metadata["sha256"] = sha256
        md5 = hashlib.md5(self.data).hexdigest()
        metadata["md5"] = md5
        file_type = magic.from_buffer(self.data)
        metadata["file_type"] = file_type
        return metadata

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        chaines_ascii = re.findall(rb"[\x20-\x7e]{4,}", self.data)
        chaines_texte = []
        for chaine in chaines_ascii:
            chaines_texte.append(chaine.decode("utf8"))
        ips_candidates = []
        for texte in chaines_texte:
            trouvees = re.findall(
                r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])",
                texte
            )
            ips_candidates.extend(trouvees)

        ips_valides = []

        for candidate in ips_candidates:
            try:
                adresse = ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            ips_valides.append(str(adresse))
        ips_valides = sorted(set(ips_valides))

        urls_candidates = []

        for texte in chaines_texte:
            trouvees = re.findall(r"https?://[^\s<>\"']+", texte)
            urls_candidates.extend(trouvees)

        urls_valides = []

        for candidate in urls_candidates:
            try:
                elements = urlsplit(candidate)
                hote = elements.hostname
            except ValueError:
                continue

            if elements.scheme in ("http", "https") and hote:
                urls_valides.append(candidate)

        urls_valides = sorted(set(urls_valides))

        hotes_candidates = []

        for url in urls_valides:
            hote = urlsplit(url).hostname
            if hote:
                hotes_candidates.append(hote)

        motif_domaine = (
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            r"[A-Za-z]{2,63}"
        )

        domaines = []

        for hote in hotes_candidates:
            try:
                ipaddress.ip_address(hote)
            except ValueError:
                    if len(hote) <= 253 and re.fullmatch(motif_domaine, hote):
                        domaines.append(hote)

        domaines = sorted(set(domaines))

        mutex_candidates = []

        for texte in chaines_texte:
            trouvees = re.findall(
                r"(?<![A-Za-z0-9_])(?:Global|Local)\\[A-Za-z0-9_.-]+",
                texte,
            )
            mutex_candidates.extend(trouvees)

        mutex = sorted(set(mutex_candidates))

        registry_candidates = []

        for texte in chaines_texte:
            trouvees = re.findall(
                r"(?<![A-Za-z0-9_])"
                r"(?:HKCU|HKLM|HKCR|HKU|HKCC|"
                r"HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|"
                r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)"
                r"\\[^\s\"'<>]+",
                texte,
                flags=re.IGNORECASE,
            )
            registry_candidates.extend(trouvees)

        registry = sorted(set(registry_candidates))

        return {
            "domains": domaines,
            "ips": ips_valides,
            "urls": urls_valides,
            "mutex": mutex,
            "registry": registry,
        }
    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        resultat = {
            "format": None,
            "sections": [],
            "imports": [],
            "exports": [],
        }

        if not self.data.startswith((b"MZ", b"\x7fELF")):
            return resultat

        binaire = lief.parse(list(self.data))

        if binaire is None:
            return resultat

        if isinstance(binaire, lief.PE.Binary):
            resultat["format"] = "PE"
        elif isinstance(binaire, lief.ELF.Binary):
            resultat["format"] = "ELF"
        else:
            return resultat

        for section in binaire.sections:
            resultat["sections"].append(
                {
                    "name": section.name,
                    "size": section.size,
                    "entropy": section.entropy,
                }
            )

        imports = []
        for fonction in binaire.imported_functions:
            if fonction.name:
                imports.append(fonction.name)

        exports = []
        for fonction in binaire.exported_functions:
            if fonction.name:
                exports.append(fonction.name)

        resultat["imports"] = sorted(set(imports))
        resultat["exports"] = sorted(set(exports))

        return resultat