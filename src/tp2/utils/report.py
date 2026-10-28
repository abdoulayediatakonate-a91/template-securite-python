import json
from fpdf import FPDF

class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        def ajouter_texte(texte):
            texte = str(texte).encode("latin-1", errors="replace").decode("latin-1")
            pdf.multi_cell(
                0,
                6,
                text=texte,
                new_x="LMARGIN",
                new_y="NEXT",
            )

        pdf.set_font("Helvetica", size=16)
        ajouter_texte("Rapport de triage statique")
        pdf.ln(4)

        pdf.set_font("Helvetica", size=10)
        ajouter_texte(f"SHA-256 : {self.result.get('sha256', 'Non disponible')}")
        ajouter_texte(f"Taille : {self.result.get('size', 0)} octets")
        ajouter_texte(f"Type : {self.result.get('file_type', 'Non disponible')}")
        ajouter_texte(f"Famille : {self.result.get('family_guess', 'indeterminee')}")
        ajouter_texte(f"Score heuristique : {self.result.get('score', 0)}/10")

        pdf.ln(4)
        ajouter_texte("Synthese")
        ajouter_texte(self.result.get("llm_summary", "Synthese non disponible"))

        pdf.ln(4)
        ajouter_texte("Regles YARA declenchees")
        matches = self.result.get("yara_matches", [])
        ajouter_texte(", ".join(matches) if matches else "Aucune")

        pdf.ln(4)
        ajouter_texte("Indicateurs extraits")
        iocs = self.result.get("iocs", {})
        for categorie in ("domains", "ips", "urls", "mutex", "registry"):
            ajouter_texte(f"{categorie} :")
            valeurs = iocs.get(categorie, [])
            if not valeurs:
                ajouter_texte("  Aucun")
            for valeur in valeurs:
                ajouter_texte(f"  - {valeur}")

        pdf.output(out_pdf)

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        with open(out_json, "w", encoding="utf-8") as fichier:
            json.dump(self.result, fichier, ensure_ascii=False, indent=4)
