from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from ..core import unique


MAX_IOC_SCAN_BYTES = 2 * 1024 * 1024
MAX_IOCS_PER_TYPE = 100

URL_RE = re.compile(r"\bhttps?://[^\s'\"<>)\]}]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]{0,39}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")

TRAILING_URL_PUNCTUATION = ".,;:!?)]}\"'"
COMMON_FILE_EXTENSION_TLDS = {
    "7z",
    "bat",
    "bin",
    "bz2",
    "cmd",
    "css",
    "dll",
    "doc",
    "docm",
    "docx",
    "exe",
    "gif",
    "gz",
    "html",
    "jar",
    "jpeg",
    "jpg",
    "js",
    "json",
    "pdf",
    "png",
    "ppt",
    "pptm",
    "pptx",
    "ps1",
    "py",
    "rar",
    "sh",
    "tar",
    "txt",
    "vbs",
    "war",
    "xls",
    "xlsm",
    "xlsx",
    "xml",
    "zip",
}


def empty_iocs() -> dict[str, list[str]]:
    return {"urls": [], "ips": [], "domains": []}


def extract_iocs_from_file(path: Path, max_bytes: int = MAX_IOC_SCAN_BYTES) -> dict[str, list[str]]:
    with path.open("rb") as file:
        data = file.read(max_bytes)

    return extract_iocs_from_text(_text_from_bytes(data))


def extract_iocs_from_text(text: str) -> dict[str, list[str]]:
    urls = unique(_extract_urls(text), MAX_IOCS_PER_TYPE)
    ips = unique(_extract_ips(text), MAX_IOCS_PER_TYPE)
    domains = unique(_extract_domains(text, urls), MAX_IOCS_PER_TYPE)

    return {
        "urls": urls,
        "ips": ips,
        "domains": domains,
    }


def merge_iocs(collections: list[dict]) -> dict[str, list[str]]:
    merged = empty_iocs()

    for collection in collections:
        if not isinstance(collection, dict):
            continue

        for key in merged:
            values = collection.get(key, [])
            if isinstance(values, list):
                merged[key].extend(str(value) for value in values if value)

    return {key: unique(values, MAX_IOCS_PER_TYPE) for key, values in merged.items()}


def ioc_count(iocs: dict[str, list[str]]) -> int:
    return sum(len(values) for values in iocs.values())


def _extract_urls(text: str) -> list[str]:
    urls = []

    for match in URL_RE.finditer(text):
        url = _normalize_url(match.group(0))
        if url:
            urls.append(url)

    return urls


def _extract_ips(text: str) -> list[str]:
    ips = []

    for regex in (IPV4_RE, IPV6_RE):
        for match in regex.finditer(text):
            ip = _normalize_ip(match.group(0))
            if ip:
                ips.append(ip)

    return ips


def _extract_domains(text: str, urls: list[str]) -> list[str]:
    domains = []

    for url in urls:
        host = urlparse(url).hostname
        if not host:
            continue
        host = host.lower().strip(".")
        if _normalize_ip(host):
            continue
        if _valid_domain(host, allow_file_extension_tld=True):
            domains.append(host)

    for match in DOMAIN_RE.finditer(text):
        domain = match.group(0).lower().strip(".")
        if _valid_domain(domain):
            domains.append(domain)

    return domains


def _normalize_url(value: str) -> str | None:
    value = value.strip().rstrip(TRAILING_URL_PUNCTUATION)
    parsed = urlparse(value)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None

    return value


def _normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def _valid_domain(value: str, allow_file_extension_tld: bool = False) -> bool:
    if not value or len(value) > 253 or "." not in value:
        return False

    if _normalize_ip(value):
        return False

    labels = value.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return False

    tld = labels[-1]
    if not tld.isalpha():
        return False

    if not allow_file_extension_tld and tld in COMMON_FILE_EXTENSION_TLDS:
        return False

    return True


def _text_from_bytes(data: bytes) -> str:
    if not data:
        return ""

    printable = sum(1 for byte in data if byte in b"\n\r\t" or 32 <= byte <= 126)
    if printable / len(data) > 0.75:
        return data.decode("utf-8", errors="replace")

    return "\n".join(match.group(0).decode("ascii", errors="ignore") for match in ASCII_STRING_RE.finditer(data))
