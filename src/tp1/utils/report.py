# Génération des rapports : CSV, SVG et PDF
# Chaque format est encapsulé dans sa propre classe.
# La classe Report orchestre l'ensemble.

import csv
import os
import tempfile

import pygal
from PIL import Image, ImageDraw
from fpdf import FPDF
from fpdf.enums import XPos, YPos

from tp1.utils.capture import Capture

# Rapport CSV

class CsvReport:
    """Génère un fichier CSV avec 3 sections : protocoles, IPs, attaques."""

    def __init__(self, capture: Capture) -> None:
        self.capture = capture

    def generate(self, filename: str = "protocol_table.csv") -> str:
        """Écrit le fichier CSV et retourne son nom."""
        with open(filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)

            # Section protocoles
            writer.writerow(["=== PROTOCOL TABLE ==="])
            writer.writerow(["Protocol", "Packet count"])
            for proto, count in self.capture.protocol_counter.items():
                writer.writerow([proto, count])

            writer.writerow([])

            # Section IPs
            writer.writerow(["=== IP TABLE ==="])
            writer.writerow(["IP Address", "Packet count", "Protocols"])
            sorted_ips = sorted(
                self.capture.ip_packet_counter.items(), key=lambda x: x[1], reverse=True
            )
            for ip, count in sorted_ips:
                proto_details = ", ".join(
                    f"{p}: {c}"
                    for p, c in sorted(self.capture.ip_proto_counter.get(ip, {}).items())
                )
                writer.writerow([ip, count, proto_details])

            writer.writerow([])

            # Section attaques
            writer.writerow(["=== ATTACKS DETECTED ==="])
            if not self.capture.suspicious:
                writer.writerow(["No attacks detected."])
            else:
                for alert in self.capture.suspicious:
                    writer.writerow([alert])

        return filename

# Rapport graphique (SVG via pygal)

class GraphReport:
    """Génère un graphique SVG interactif des protocoles avec pygal."""

    def __init__(self, capture: Capture) -> None:
        self.capture = capture

    def generate(self, filename: str = "network_graph.svg") -> str:
        """Crée le fichier SVG et retourne son nom."""
        bar_chart = pygal.Bar()
        bar_chart.title = "Network Traffic per Protocol"
        for proto, count in self.capture.protocol_counter.items():
            bar_chart.add(proto, count)
        bar_chart.render_to_file(filename)
        return filename

# Rapport PDF

class PdfReport:
    """
    Génère un rapport PDF complet :
    en-tête, graphique, tableau des protocoles, tableau des IPs, analyse.
    """

    # Palette de couleurs pour le bar chart Pillow
    _BAR_COLORS = ["#F44336", "#3F51B5", "#009688", "#FFC107", "#FF5722"]

    def __init__(self, capture: Capture, summary: str) -> None:
        self.capture = capture
        self.summary = summary

    # Sections PDF

    def _write_header(self, pdf: FPDF) -> None:
        """En-tête : titre et métadonnées interface / paquets."""
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(
            0, 10, "RAPPORT IDS - ANALYSE RESEAU",
            align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )
        pdf.ln(3)
        pdf.set_font("Helvetica", size=10)
        for line in self.summary.split("\n"):
            line = line.strip()
            if line.startswith("Interface:") or line.startswith("Total packets"):
                pdf.cell(0, 6, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

    def _write_chart(self, pdf: FPDF) -> None:
        """Génère le bar chart PNG avec Pillow et l'insère dans le PDF."""
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Graphique du trafic reseau", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp.close()
        try:
            self._draw_bar_chart(tmp.name)
            pdf.image(tmp.name, x=15, w=175)
        finally:
            os.unlink(tmp.name)
        pdf.ln(5)

    def _draw_bar_chart(self, path: str) -> None:
        """Dessine le bar chart avec Pillow et sauvegarde en PNG."""
        protocols = list(self.capture.protocol_counter.keys())
        counts = list(self.capture.protocol_counter.values())
        max_count = max(counts) if counts else 1
        n = len(protocols) if protocols else 1

        margin_left, margin_top, margin_bottom = 60, 50, 50
        W = max(750, margin_left + 20 + n * 80)
        H = 350

        img = Image.new("RGB", (W, H), "white")
        draw = ImageDraw.Draw(img)

        chart_w = W - margin_left - 20
        chart_h = H - margin_top - margin_bottom
        bar_slot = chart_w // n
        bar_w = max(bar_slot - 20, 20)

        # Axes
        draw.text((W // 2, 15), "Network Traffic per Protocol", fill="black", anchor="mt")
        draw.line([margin_left, margin_top, margin_left, margin_top + chart_h], fill="black", width=2)
        draw.line([margin_left, margin_top + chart_h, W - 20, margin_top + chart_h], fill="black", width=2)

        # Barres
        for i, (proto, count) in enumerate(zip(protocols, counts)):
            bar_h = int((count / max_count) * chart_h)
            x = margin_left + i * bar_slot + 10
            y_top = margin_top + chart_h - bar_h
            y_bot = margin_top + chart_h
            color = self._BAR_COLORS[i % len(self._BAR_COLORS)]
            draw.rectangle([x, y_top, x + bar_w, y_bot], fill=color)
            draw.text((x + bar_w // 2, y_top - 5), str(count), fill="black", anchor="mb")
            draw.text((x + bar_w // 2, y_bot + 8), proto, fill="black", anchor="mt")

        img.save(path)

    def _write_protocol_table(self, pdf: FPDF) -> None:
        """Insère le tableau des protocoles dans le PDF."""
        if not self.capture.protocol_counter:
            return

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Tableau des protocoles", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(80, 7, "Protocole", border=1)
        pdf.cell(80, 7, "Nombre de paquets", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", size=10)
        for proto, count in sorted(
            self.capture.protocol_counter.items(), key=lambda x: x[1], reverse=True
        ):
            pdf.cell(80, 7, str(proto), border=1)
            pdf.cell(80, 7, str(count), border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

    def _write_ip_table(self, pdf: FPDF) -> None:
        """Insère le tableau des IPs avec détail des protocoles dans le PDF."""
        if not self.capture.ip_packet_counter:
            return

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Paquets par adresse IP", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(60, 7, "Adresse IP", border=1)
        pdf.cell(30, 7, "Total", border=1)
        pdf.cell(90, 7, "Detail par protocole", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", size=10)
        sorted_ips = sorted(
            self.capture.ip_packet_counter.items(), key=lambda x: x[1], reverse=True
        )
        for ip, count in sorted_ips:
            proto_details = ", ".join(
                f"{p}: {c}"
                for p, c in sorted(self.capture.ip_proto_counter.get(ip, {}).items())
            )
            pdf.cell(60, 7, str(ip), border=1)
            pdf.cell(30, 7, str(count), border=1)
            pdf.cell(90, 7, proto_details, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

    def _write_proto_analysis(self, pdf: FPDF) -> None:
        """Insère l'analyse par protocole (vert = légitime, rouge = suspect) dans le PDF."""
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Analyse par protocole", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        proto_analysis = self.capture.get_proto_analysis()
        for proto, info in sorted(proto_analysis.items()):
            is_suspect = info["status"] == "SUSPICIOUS"
            color = (200, 0, 0) if is_suspect else (0, 150, 0)
            status_label = "SUSPECT" if is_suspect else "LEGITIME"

            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*color)
            pdf.cell(
                0, 8, f"{proto}  ({info['count']} paquets) - {status_label}",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", size=10)

            if info["alerts"]:
                for alert in info["alerts"]:
                    pdf.set_text_color(200, 0, 0)
                    pdf.cell(0, 6, f"  {alert}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
            else:
                pdf.set_text_color(0, 150, 0)
                pdf.cell(0, 6, "  Aucune activite suspecte detectee.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
            pdf.ln(2)

        if not proto_analysis:
            pdf.set_font("Helvetica", size=10)
            pdf.set_text_color(0, 150, 0)
            pdf.cell(0, 7, "Tout le trafic est legitime.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)

    # Point d'entrée public

    def generate(self, filename: str) -> None:
        """Orchestre la génération complète du PDF."""
        pdf = FPDF()
        pdf.add_page()
        self._write_header(pdf)
        self._write_chart(pdf)
        self._write_protocol_table(pdf)
        self._write_ip_table(pdf)
        self._write_proto_analysis(pdf)
        pdf.output(filename)

# Orchestrateur principal

class Report:
    """
    Orchestre la génération du rapport complet.
    Délègue à CsvReport, GraphReport et PdfReport selon le format demandé.
    """

    def __init__(self, capture: Capture, filename: str, summary: str) -> None:
        self.capture = capture
        self.filename = filename
        self.summary = summary
        self.title = "TITRE DU RAPPORT\n"

        # Sous-rapports
        self._csv = CsvReport(capture)
        self._graph = GraphReport(capture)
        self._pdf = PdfReport(capture, summary)

        # Noms des fichiers générés (remplis après generate())
        self._csv_file: str = ""
        self._graph_file: str = ""

    def generate(self, param: str) -> None:
        """
        Génère le fichier correspondant au paramètre :
        - "array" → CSV
        - "graph" → SVG
        """
        if param == "array":
            self._csv_file = self._csv.generate()
        elif param == "graph":
            self._graph_file = self._graph.generate()

    def save(self, filename: str = None) -> None:
        """
        Sauvegarde le rapport final :
        - .pdf  → génère le PDF complet via PdfReport
        - autre → écrit un rapport texte
        """
        filename = filename or self.filename

        if filename.endswith(".pdf"):
            self._pdf.generate(filename)
        else:
            with open(filename, "w") as f:
                f.write(self._build_text_report())

    def _build_text_report(self) -> str:
        """Construit le rapport texte en concaténant titre, résumé, CSV et graphique."""
        parts = [self.title, self.summary]
        if self._csv_file:
            parts.append(f"CSV: {self._csv_file}\n")
        if self._graph_file:
            parts.append(f"Graph: {self._graph_file}\n")
        return "\n".join(parts)
