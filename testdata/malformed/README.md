# Malformed Sample Fixtures

These files are intentionally broken so you can test MALCORE's upload, metadata, analyzer, and reporting flows without using real malware.

## Files

- `truncated.zip`
  - Starts like a ZIP archive but is truncated and should fail archive parsing.
- `invalid.docx`
  - Uses an Office OOXML extension but contains plain text instead of a valid ZIP container.
- `broken.exe`
  - Starts with an `MZ` header but does not contain a valid PE structure.

## Suggested Tests

- Upload each file through the web UI.
- Submit them through the API directly.
- Confirm MALCORE stores hashes and MIME metadata.
- Confirm analyzers return safe errors and findings instead of crashing.
- Confirm JSON and PDF reports still generate for failed or partially parsed samples.
