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
        triage = Triage(str(chemin), args.llm)
        result = triage.run()

        report = Report(result)
        report.generate_pdf(f"{args.file}.triage.pdf")
        report.generate_json(f"{args.file}.triage.json")


if __name__ == "__main__":
    main()
