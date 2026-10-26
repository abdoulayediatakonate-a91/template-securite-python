from pathlib import Path
import yara

class YaraScanner:
    def __init__(self, rules_path: str = "rules/course_rules.yar") -> None:
        self.rules_path = rules_path

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        chemin = Path(self.rules_path)

        if chemin.is_file():
            fichiers = [chemin]
        elif chemin.is_dir():
            fichiers = sorted(chemin.rglob("*.yar"))
            fichiers += sorted(chemin.rglob("*.yara"))
        else:
            raise FileNotFoundError(
                f"Chemin des règles YARA introuvable : {chemin}"
            )

        if not fichiers:
            raise ValueError(
                f"Aucun fichier de règles YARA trouvé dans : {chemin}"
            )

        chemins_regles = {}

        for numero, fichier in enumerate(fichiers):
            chemins_regles[f"regles_{numero}"] = str(fichier)

        regles = yara.compile(filepaths=chemins_regles)
        correspondances = regles.match(data=data, timeout=30)

        noms = []

        for correspondance in correspondances:
            noms.append(correspondance.rule)

        return sorted(set(noms))
