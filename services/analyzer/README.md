# MALCORE Analyzer

Python static analyzer framework for MALCORE.

## Usage

From the repository root:

```bash
python3 services/analyzer/analyze.py /path/to/sample --pretty
```

From `services/analyzer`:

```bash
python3 -m analyzers.cli /path/to/sample --pretty
```

The CLI accepts a file path and emits a JSON result.

## Analyzer Layout

```text
analyzers/
  pe/
  scripts/
  office/
  archive/
```

This first version is dependency-light and does not execute samples. It performs static file inspection only.
