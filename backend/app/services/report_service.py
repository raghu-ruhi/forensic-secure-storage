import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_evidence_report(evidence, uploader, ledger_blocks, signatures,
                              chain_valid: dict, output_path: str) -> str:
    """Build a PDF forensic report: case details, evidence details, hashes,
    verification status, signature status, and audit trail.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=18)
    heading_style = ParagraphStyle("HeadingStyle", parent=styles["Heading2"], spaceBefore=14)

    story = []
    story.append(Paragraph("Digital Forensic Evidence Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()} UTC", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Case / evidence details
    story.append(Paragraph("Case &amp; Evidence Details", heading_style))
    details_data = [
        ["Case Number", evidence.case_number],
        ["Evidence Title", evidence.title],
        ["Description", evidence.description or "-"],
        ["Original Filename", evidence.original_filename],
        ["File Size (bytes)", str(evidence.file_size_bytes)],
        ["Uploaded By", f"{uploader.full_name} ({uploader.email})"],
        ["Upload Timestamp", evidence.created_at.isoformat() if evidence.created_at else "-"],
        ["Current Status", evidence.status.upper()],
        ["Replicated Nodes", ", ".join(evidence.replicated_nodes.split(",")) if evidence.replicated_nodes else "-"],
    ]
    details_table = Table(details_data, colWidths=[5 * cm, 11 * cm])
    details_table.setStyle(_default_table_style())
    story.append(details_table)
    story.append(Spacer(1, 0.5 * cm))

    # Hash / integrity
    story.append(Paragraph("Integrity Verification", heading_style))
    integrity_data = [
        ["SHA-256 Hash (at upload)", evidence.sha256_hash],
        ["Blockchain Ledger Valid", "YES" if chain_valid.get("valid") else "NO — TAMPERING DETECTED"],
        ["Total Ledger Blocks", str(chain_valid.get("total_blocks", 0))],
        ["Last Verified", evidence.last_verified_at.isoformat() if evidence.last_verified_at else "Never"],
    ]
    integrity_table = Table(integrity_data, colWidths=[5 * cm, 11 * cm])
    integrity_table.setStyle(_default_table_style())
    story.append(integrity_table)
    story.append(Spacer(1, 0.5 * cm))

    # Digital signatures
    story.append(Paragraph("Digital Signature Status", heading_style))
    if signatures:
        sig_data = [["Signer ID", "Signed Hash", "Signed At"]]
        for sig in signatures:
            sig_data.append([sig.signer_id, sig.signed_hash[:16] + "...", sig.created_at.isoformat()])
        sig_table = Table(sig_data, colWidths=[5 * cm, 6 * cm, 5 * cm])
        sig_table.setStyle(_default_table_style(header=True))
        story.append(sig_table)
    else:
        story.append(Paragraph("No digital signatures recorded for this evidence.", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Chain of custody / audit trail
    story.append(Paragraph("Chain-of-Custody Ledger", heading_style))
    if ledger_blocks:
        ledger_data = [["Event", "Actor", "Timestamp", "Block Hash (short)"]]
        for block in ledger_blocks:
            ledger_data.append([
                block.event_type,
                block.actor_id or "-",
                block.timestamp.isoformat(),
                block.current_hash[:16] + "...",
            ])
        ledger_table = Table(ledger_data, colWidths=[3.5 * cm, 4.5 * cm, 4.5 * cm, 3.5 * cm])
        ledger_table.setStyle(_default_table_style(header=True))
        story.append(ledger_table)
    else:
        story.append(Paragraph("No ledger events recorded.", styles["Normal"]))

    doc.build(story)
    return output_path


def _default_table_style(header: bool = False) -> TableStyle:
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")))
        style.append(("TEXTCOLOR", (0, 0), (-1, 0), colors.white))
        style.append(("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"))
    else:
        style.append(("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")))
        style.append(("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"))
    return TableStyle(style)
