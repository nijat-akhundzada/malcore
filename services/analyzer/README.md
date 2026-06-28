# MALCORE Analyzer

Python static analyzer framework for MALCORE.

## Setup

```bash
python3 -m pip install -r services/analyzer/requirements.txt
```

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

The PE analyzer uses `pefile` to extract imports, sections, and section entropy from `.exe` and `.dll` files.

The script analyzer inspects `.ps1` and `.js` files for URL indicators, Base64-looking encoded data,
and dynamic execution patterns such as PowerShell `Invoke-Expression`, encoded commands, JavaScript
`eval`, and Node.js `child_process.exec` usage.

The Office analyzer uses `oletools` to inspect Office files for VBA macro presence and suspicious
macro keywords such as auto-execution and shell execution indicators.

The archive analyzer safely inspects `.zip`, `.rar`, and `.7z` archives by extracting files into a
temporary directory, rejecting unsafe paths, enforcing entry and size limits, accepting an optional
archive password, and limiting nested archive recursion depth.

The YARA analyzer loads rules from `services/analyzer/rules` by default, scans submitted files,
and records rule matches in the analyzer JSON. These matches are saved in each job's persisted
`analysis_result`.

The IOC analyzer extracts network indicators from submitted files, including URLs, IP addresses,
and domains. Analyzer output includes both per-module `iocs` and a top-level aggregated `iocs`
object for API and frontend consumers.
