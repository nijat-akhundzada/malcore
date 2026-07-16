package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const DefaultPDFCommand = "python3"

func RenderPDF(ctx context.Context, report *Report) ([]byte, error) {
	return RenderPDFWithCommand(ctx, DefaultPDFCommand, report)
}

func RenderPDFWithCommand(ctx context.Context, command string, report *Report) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("report is required")
	}

	body, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode report JSON for PDF renderer: %w", err)
	}

	renderCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(renderCtx, command, "-c", reportLabScript)
	cmd.Stdin = bytes.NewReader(body)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if renderCtx.Err() != nil {
			return nil, fmt.Errorf("render PDF report timed out")
		}

		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = strings.TrimSpace(stdout.String())
		}
		if message == "" {
			return nil, fmt.Errorf("render PDF report: %w", err)
		}

		return nil, fmt.Errorf("render PDF report: %w: %s", err, message)
	}

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("PDF renderer returned empty output")
	}

	return stdout.Bytes(), nil
}

const reportLabScript = `
import io
import json
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def value(item, default="None"):
    if item is None:
        return default
    if isinstance(item, bool):
        return "yes" if item else "no"
    return str(item)


def paragraph(text, style):
    return Paragraph(value(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), style)


def section(title, styles):
    return [Spacer(1, 0.16 * inch), Paragraph(title, styles["Heading2"]), Spacer(1, 0.06 * inch)]


def kv_table(rows, styles):
    data = [[paragraph(label, styles["TableKey"]), paragraph(value(content), styles["TableValue"])] for label, content in rows]
    table = Table(data, colWidths=[1.7 * inch, 4.8 * inch], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def bullet_list(items, styles, empty_text="None"):
    if not items:
        return [Paragraph(empty_text, styles["BodyText"])]
    return [Paragraph("- " + value(item), styles["BodyText"]) for item in items[:40]]


report = json.load(sys.stdin)
buffer = io.BytesIO()
doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="Muted", parent=styles["BodyText"], textColor=colors.HexColor("#4b5563"), fontSize=9))
styles.add(ParagraphStyle(name="TableKey", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=9))
styles.add(ParagraphStyle(name="TableValue", parent=styles["BodyText"], fontSize=9, leading=12))

story = []
story.append(Paragraph("MALCORE Analysis Report", styles["Title"]))
story.append(Paragraph("Generated " + value(report.get("generated_at")), styles["Muted"]))

job = report.get("job") or {}
file_info = report.get("file") or {}
hashes = report.get("hashes") or {}
scores = report.get("scores") or {}
iocs = report.get("iocs") or {}
yara_hits = report.get("yara_hits") or []

story.extend(section("Summary", styles))
story.append(kv_table([
    ("Job ID", job.get("id")),
    ("Source", job.get("source_type")),
    ("Status", job.get("status")),
    ("Risk level", scores.get("risk_level")),
    ("Final score", scores.get("final")),
    ("Rule score", scores.get("rule")),
    ("AI score", scores.get("ai")),
], styles))

story.extend(section("File", styles))
story.append(kv_table([
    ("MIME type", file_info.get("mime_type")),
    ("Extension", file_info.get("extension")),
    ("Size bytes", file_info.get("size_bytes")),
    ("MIME mismatch", file_info.get("mime_extension_mismatch")),
    ("Original object", file_info.get("original_storage_key")),
    ("Quarantine object", file_info.get("quarantine_storage_key")),
], styles))

story.extend(section("Hashes", styles))
story.append(kv_table([
    ("MD5", hashes.get("md5")),
    ("SHA256", hashes.get("sha256")),
], styles))

story.extend(section("YARA Hits", styles))
if yara_hits:
    rows = [["Rule", "Severity", "Description"]]
    for hit in yara_hits[:25]:
        rows.append([
            paragraph(hit.get("rule"), styles["TableValue"]),
            paragraph(hit.get("severity"), styles["TableValue"]),
            paragraph(hit.get("description"), styles["TableValue"]),
        ])
    table = Table(rows, colWidths=[2.2 * inch, 1.0 * inch, 3.3 * inch], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fee2e2")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)
else:
    story.append(Paragraph("No YARA hits.", styles["BodyText"]))

story.extend(section("Indicators", styles))
story.append(Paragraph("URLs", styles["Heading3"]))
story.extend(bullet_list(iocs.get("urls") or [], styles))
story.append(Paragraph("IP addresses", styles["Heading3"]))
story.extend(bullet_list(iocs.get("ips") or [], styles))
story.append(Paragraph("Domains", styles["Heading3"]))
story.extend(bullet_list(iocs.get("domains") or [], styles))

story.extend(section("Scoring", styles))
story.append(kv_table([
    ("Formula", scores.get("formula")),
    ("Rule weight", (scores.get("weights") or {}).get("rule")),
    ("AI weight", (scores.get("weights") or {}).get("ai")),
    ("AI model", (scores.get("ai_model") or {}).get("name")),
    ("AI features", json.dumps((scores.get("ai_model") or {}).get("features") or {}, sort_keys=True)),
], styles))

doc.build(story)
sys.stdout.buffer.write(buffer.getvalue())
`
