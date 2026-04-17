"""
IOC (Indicator of Compromise) extraction.

Given an email's content, pulls out items that an analyst would want to
block or investigate: sender address, sender domain, URLs, URL domains,
IP addresses. These are the artifacts that turn "this is phishing"
into "here's what to block."
"""
import re
import hashlib
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Iterable
from urllib.parse import urlparse


# IOC types - matches the `ioc_type` column in the database
IOC_SENDER = "sender"
IOC_SENDER_DOMAIN = "sender_domain"
IOC_URL = "url"
IOC_URL_DOMAIN = "url_domain"
IOC_IP = "ip"
IOC_ATTACHMENT_HASH = "attachment_hash"
IOC_ATTACHMENT_NAME = "attachment_name"


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'\]\)]+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)


@dataclass
class IOC:
    """One indicator of compromise."""
    ioc_type: str
    value: str
    context: str = ""  # Optional: where/how we found it

    def __hash__(self):
        return hash((self.ioc_type, self.value.lower()))

    def __eq__(self, other):
        if not isinstance(other, IOC):
            return False
        return (self.ioc_type, self.value.lower()) == (other.ioc_type, other.value.lower())


def extract_sender_iocs(sender_header: str) -> list[IOC]:
    """Parse the From header into a clean email + domain."""
    iocs = []
    if not sender_header:
        return iocs

    # parseaddr handles "Name <email@domain.com>" and bare "email@domain.com"
    _, addr = parseaddr(sender_header)
    if not addr or "@" not in addr:
        return iocs

    addr = addr.lower().strip()
    iocs.append(IOC(IOC_SENDER, addr, context="From header"))

    domain = addr.split("@", 1)[1]
    if domain:
        iocs.append(IOC(IOC_SENDER_DOMAIN, domain, context="From header"))

    return iocs


def _is_valid_ip(ip: str) -> bool:
    """Sanity-check an IP string (each octet 0-255)."""
    try:
        return all(0 <= int(octet) <= 255 for octet in ip.split("."))
    except (ValueError, AttributeError):
        return False


def _extract_domain(url: str) -> str:
    """Pull the hostname from a URL, lowercase it."""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def extract_url_iocs(text: str) -> list[IOC]:
    """Pull all URLs from text. Returns both full URLs and their domains."""
    iocs = []
    if not text:
        return iocs

    # De-duplicate URLs by their normalized form (lowercased, trailing punctuation stripped)
    seen_urls = set()
    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,;:!?)")
        key = url.lower()
        if key in seen_urls:
            continue
        seen_urls.add(key)

        iocs.append(IOC(IOC_URL, url, context="body"))

        domain = _extract_domain(url)
        if domain:
            iocs.append(IOC(IOC_URL_DOMAIN, domain, context=f"from {url}"))

            # If the URL's host is an IP address, that's worth flagging separately
            if _is_valid_ip(domain):
                iocs.append(IOC(IOC_IP, domain, context=f"IP-based URL"))

    return iocs


def extract_ip_iocs(text: str) -> list[IOC]:
    """Find bare IP addresses in text (outside URLs)."""
    iocs = []
    if not text:
        return iocs

    seen = set()
    for match in IP_PATTERN.finditer(text):
        ip = match.group(0)
        if not _is_valid_ip(ip):
            continue
        if ip in seen:
            continue
        # Skip private/local ranges - not useful as block targets
        if ip.startswith(("10.", "192.168.", "127.", "0.")):
            continue
        seen.add(ip)
        iocs.append(IOC(IOC_IP, ip, context="body"))

    return iocs


def extract_attachment_iocs(attachments: Iterable) -> list[IOC]:
    """For each attachment, produce a name IOC and a SHA-256 hash IOC.

    `attachments` is expected to be an iterable of imap_tools MailAttachment
    objects (with .filename and .payload attributes).
    """
    iocs = []
    for att in attachments or []:
        filename = getattr(att, "filename", None) or "<unnamed>"
        payload = getattr(att, "payload", b"") or b""

        iocs.append(IOC(IOC_ATTACHMENT_NAME, filename, context="attachment"))

        if payload:
            sha256 = hashlib.sha256(payload).hexdigest()
            iocs.append(IOC(
                IOC_ATTACHMENT_HASH,
                sha256,
                context=f"sha256 of {filename}",
            ))

    return iocs


def extract_all_iocs(
    sender: str,
    subject: str,
    body: str,
    attachments: Iterable = (),
) -> list[IOC]:
    """Top-level: pull all IOCs from an email.

    Returns a de-duplicated list (same type + value = one IOC).
    """
    all_iocs = []
    all_iocs.extend(extract_sender_iocs(sender))

    # Look for URLs and IPs in both subject and body
    combined_text = f"{subject or ''}\n{body or ''}"
    all_iocs.extend(extract_url_iocs(combined_text))
    all_iocs.extend(extract_ip_iocs(combined_text))

    all_iocs.extend(extract_attachment_iocs(attachments))

    # De-dupe while preserving order
    seen = set()
    deduped = []
    for ioc in all_iocs:
        key = (ioc.ioc_type, ioc.value.lower())
        if key not in seen:
            seen.add(key)
            deduped.append(ioc)

    return deduped