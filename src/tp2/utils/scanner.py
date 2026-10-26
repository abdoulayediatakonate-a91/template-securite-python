from pathlib import Path

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
        raise NotImplementedError
