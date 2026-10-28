import argparse

from pathlib import Path
from tp2.utils.report import Report
from tp2.utils.triage import Triage

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args()

    dossier_samples = Path(args.samples)
    dossier_sortie = Path(args.out)
    dossier_sortie.mkdir(parents=True, exist_ok=True)

    for chemin in dossier_samples.iterdir():
     if chemin.is_file():
        triage = Triage(str(chemin), args.llm, args.rules)
        result = triage.run()

        report = Report(result)
        chemin_json = dossier_sortie / f"{chemin.name}.triage.json"
        report.generate_json(str(chemin_json))
        chemin_pdf = dossier_sortie / f"{chemin.name}.triage.pdf"
        report.generate_pdf(str(chemin_pdf))

if __name__ == "__main__":
    main()
