from fpdf import FPDF
import hashlib
from datetime import datetime

class ForensicReport:
    def __init__(self, investigator="Manaswee Balvant Nadgouda"):
        self.investigator = investigator

    def file_hash(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def generate(self, output_path, case_id, summary, evidence_files=None):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Forensic Investigation Report", ln=True, align="C")

        pdf.set_font("Arial", "", 12)
        pdf.ln(4)
        pdf.cell(0, 8, f"Case ID: {case_id}", ln=True)
        pdf.cell(0, 8, f"Investigator: {self.investigator}", ln=True)
        pdf.cell(0, 8, f"Date: {datetime.utcnow().isoformat()}Z", ln=True)

        pdf.ln(6)
        pdf.set_font("Arial", "B", 13)
        pdf.cell(0, 8, "Executive Summary", ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.multi_cell(0, 7, summary)

        if evidence_files:
            pdf.ln(4)
            pdf.set_font("Arial", "B", 13)
            pdf.cell(0, 8, "Evidence Chain of Custody", ln=True)
            pdf.set_font("Arial", "", 11)
            for p in evidence_files:
                try:
                    h = self.file_hash(p)
                    pdf.multi_cell(0, 6, f"{p} — SHA-256: {h}")
                except Exception as e:
                    pdf.multi_cell(0, 6, f"{p} — ERROR hashing file: {e}")

        pdf.output(output_path)
        return output_path
