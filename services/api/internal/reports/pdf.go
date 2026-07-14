package reports

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

const (
	pdfPageWidth    = 595
	pdfPageHeight   = 842
	pdfLeftMargin   = 50
	pdfTopMargin    = 790
	pdfBottomMargin = 50
	pdfLineHeight   = 16
	pdfCharsPerLine = 90
)

func RenderPDF(report *Report) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("report is required")
	}

	lines := reportLines(report)
	pages := paginateLines(lines)

	return buildPDFDocument(pages), nil
}

func reportLines(report *Report) []string {
	lines := []string{
		"MALCORE Analysis Report",
		"",
		fmt.Sprintf("Generated at: %s", report.GeneratedAt),
		fmt.Sprintf("Job ID: %s", report.Job.ID),
		fmt.Sprintf("Source type: %s", report.Job.SourceType),
		fmt.Sprintf("Status: %s", report.Job.Status),
		"",
		"Executive Summary",
		fmt.Sprintf("Risk level: %s", stringOrDefault(riskString(report.Scoring.RiskLevel), "pending")),
		fmt.Sprintf("Final score: %s", intString(report.Scoring.FinalScore)),
		fmt.Sprintf("AI score: %s", intString(report.Scoring.AIScore)),
		fmt.Sprintf("Rule score: %s", intString(report.Scoring.RuleScore)),
		"",
		"File Metadata",
		fmt.Sprintf("MIME type: %s", derefString(report.File.MIMEType)),
		fmt.Sprintf("Extension: %s", derefString(report.File.FileExtension)),
		fmt.Sprintf("Size: %s bytes", int64String(report.File.SizeBytes)),
		fmt.Sprintf("MIME mismatch: %t", report.File.MIMEExtensionMismatch),
		fmt.Sprintf("MD5: %s", derefString(report.File.Hashes.MD5)),
		fmt.Sprintf("SHA256: %s", derefString(report.File.Hashes.SHA256)),
		"",
		"Indicators of Compromise",
	}

	lines = append(lines, sectionFromIOCs(report.Analysis.IOCs)...)
	lines = append(lines,
		"",
		"YARA Hits",
	)
	lines = append(lines, sectionFromYARAHits(report.Analysis.YARAHits)...)
	lines = append(lines,
		"",
		"Findings",
	)
	lines = append(lines, sectionFromFindings(report.Analysis.Findings)...)
	lines = append(lines,
		"",
		"Modules",
	)
	lines = append(lines, sectionFromModules(report.Analysis.Modules)...)

	return wrapLines(lines, pdfCharsPerLine)
}

func sectionFromIOCs(iocs map[string][]string) []string {
	keys := []string{"urls", "ips", "domains"}
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		values := iocs[key]
		if len(values) == 0 {
			lines = append(lines, fmt.Sprintf("%s: none", strings.ToUpper(key)))
			continue
		}

		lines = append(lines, fmt.Sprintf("%s:", strings.ToUpper(key)))
		for _, value := range values {
			lines = append(lines, "  - "+value)
		}
	}
	return lines
}

func sectionFromYARAHits(hits []ReportYARAHit) []string {
	if len(hits) == 0 {
		return []string{"No YARA hits recorded."}
	}

	lines := make([]string, 0, len(hits)*2)
	for _, hit := range hits {
		line := fmt.Sprintf("- %s [%s]", hit.Rule, stringOrDefault(hit.Severity, "unknown"))
		if hit.Description != "" {
			line += " - " + hit.Description
		}
		lines = append(lines, line)
	}
	return lines
}

func sectionFromFindings(findings []ReportFinding) []string {
	if len(findings) == 0 {
		return []string{"No analyzer findings recorded."}
	}

	lines := make([]string, 0, len(findings)*2)
	for _, finding := range findings {
		lines = append(lines, fmt.Sprintf("- [%s] %s: %s", strings.ToUpper(stringOrDefault(finding.Severity, "info")), finding.Analyzer, finding.Type))
		if finding.Description != "" {
			lines = append(lines, "  "+finding.Description)
		}
	}
	return lines
}

func sectionFromModules(modules []ReportModule) []string {
	if len(modules) == 0 {
		return []string{"No analyzer modules recorded."}
	}

	lines := make([]string, 0, len(modules)*4)
	for _, module := range modules {
		lines = append(lines, fmt.Sprintf("- %s (%s)", module.Analyzer, stringOrDefault(module.Category, "uncategorized")))
		lines = append(lines, fmt.Sprintf("  supported=%t findings=%d errors=%d", module.Supported, len(module.Findings), len(module.Errors)))
		if len(module.Metadata) > 0 {
			keys := make([]string, 0, len(module.Metadata))
			for key := range module.Metadata {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			lines = append(lines, "  metadata keys: "+strings.Join(keys, ", "))
		}
	}
	return lines
}

func wrapLines(lines []string, width int) []string {
	wrapped := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			wrapped = append(wrapped, "")
			continue
		}

		remaining := line
		for len(remaining) > width {
			cut := strings.LastIndex(remaining[:width], " ")
			if cut <= 0 {
				cut = width
			}
			wrapped = append(wrapped, strings.TrimSpace(remaining[:cut]))
			remaining = strings.TrimSpace(remaining[cut:])
		}
		wrapped = append(wrapped, remaining)
	}
	return wrapped
}

func paginateLines(lines []string) [][]string {
	linesPerPage := (pdfTopMargin - pdfBottomMargin) / pdfLineHeight
	if linesPerPage <= 0 {
		linesPerPage = 40
	}

	pages := [][]string{}
	for len(lines) > 0 {
		end := linesPerPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, append([]string(nil), lines[:end]...))
		lines = lines[end:]
	}
	return pages
}

func buildPDFDocument(pages [][]string) []byte {
	objectCount := 3 + (2 * len(pages))
	objects := make([]string, 0, objectCount)

	pageIDs := make([]int, 0, len(pages))
	contentIDs := make([]int, 0, len(pages))
	nextID := 4
	for range pages {
		pageIDs = append(pageIDs, nextID)
		contentIDs = append(contentIDs, nextID+1)
		nextID += 2
	}

	objects = append(objects, "<< /Type /Catalog /Pages 2 0 R >>")

	kids := make([]string, 0, len(pageIDs))
	for _, pageID := range pageIDs {
		kids = append(kids, fmt.Sprintf("%d 0 R", pageID))
	}
	objects = append(objects, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pageIDs)))
	objects = append(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	for index, pageLines := range pages {
		pageObj := fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", pdfPageWidth, pdfPageHeight, contentIDs[index])
		objects = append(objects, pageObj)

		stream := pageContentStream(pageLines)
		contentObj := fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream)
		objects = append(objects, contentObj)
	}

	return serializePDF(objects)
}

func pageContentStream(lines []string) string {
	var builder strings.Builder
	builder.WriteString("BT\n/F1 12 Tf\n")
	builder.WriteString(fmt.Sprintf("%d %d Td\n", pdfLeftMargin, pdfTopMargin))

	for index, line := range lines {
		if index > 0 {
			builder.WriteString(fmt.Sprintf("0 -%d Td\n", pdfLineHeight))
		}
		builder.WriteString(fmt.Sprintf("(%s) Tj\n", escapePDFText(line)))
	}

	builder.WriteString("ET")
	return builder.String()
}

func serializePDF(objects []string) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("%PDF-1.4\n")

	offsets := make([]int, len(objects)+1)
	for index, object := range objects {
		offsets[index+1] = buffer.Len()
		buffer.WriteString(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", index+1, object))
	}

	xrefOffset := buffer.Len()
	buffer.WriteString(fmt.Sprintf("xref\n0 %d\n", len(objects)+1))
	buffer.WriteString("0000000000 65535 f \n")
	for _, offset := range offsets[1:] {
		buffer.WriteString(fmt.Sprintf("%010d 00000 n \n", offset))
	}

	buffer.WriteString(fmt.Sprintf("trailer << /Size %d /Root 1 0 R >>\n", len(objects)+1))
	buffer.WriteString(fmt.Sprintf("startxref\n%d\n%%%%EOF", xrefOffset))

	return buffer.Bytes()
}

func escapePDFText(text string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "(", "\\(", ")", "\\)")
	return replacer.Replace(text)
}

func derefString(value *string) string {
	if value == nil || strings.TrimSpace(*value) == "" {
		return "unknown"
	}
	return *value
}

func intString(value *int) string {
	if value == nil {
		return "pending"
	}
	return fmt.Sprintf("%d", *value)
}

func int64String(value *int64) string {
	if value == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *value)
}

func riskString(value *jobs.RiskLevel) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func stringOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
