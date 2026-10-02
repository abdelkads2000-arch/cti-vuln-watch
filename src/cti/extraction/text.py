"""Text utilities: CVE detection, HTML sanitization, sentence segmentation.

Collected content is untrusted. Sanitization removes content a human reader would
not see (scripts, hidden elements, zero-width / bidi control characters): these
are the usual carriers of prompt-injection payloads aimed at the LLM stage.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata

from bs4 import BeautifulSoup

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
_INVISIBLE_RE = re.compile(
    "[​-‏‪-‮⁠-⁤⁦-⁩﻿­\U000e0000-\U000e007f]"
)
_HIDDEN_STYLE_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0", re.I)


def find_cves(text: str | None) -> list[str]:
    """Unique CVE ids, normalized upper-case, in order of first appearance."""
    if not text:
        return []
    seen: dict[str, None] = {}
    for m in CVE_RE.finditer(text):
        seen.setdefault(f"CVE-{m.group(1)}-{m.group(2)}", None)
    return list(seen)


def strip_invisible(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_RE.sub("", text)
    # Remaining control chars except newline / tab.
    return "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")


def html_to_text(html: str, *, root_selector: str | None = None) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript", "template", "iframe", "svg", "head", "form"]):
        tag.decompose()
    for tag in soup.find_all(True):
        if tag.decomposed:
            continue
        attrs = tag.attrs or {}
        if (
            "hidden" in attrs
            or attrs.get("aria-hidden") == "true"
            or _HIDDEN_STYLE_RE.search(str(attrs.get("style", "")))
        ):
            tag.decompose()
    root = soup.select_one(root_selector) if root_selector else None
    root = root or soup.body or soup
    for br in root.find_all("br"):
        br.replace_with("\n")
    block_tags = ["p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section", "article"]
    for blk in root.find_all(block_tags):
        blk.insert_before("\n")
        blk.insert_after("\n")
    text = root.get_text(" ")
    return normalize_ws(strip_invisible(text))


def extract_links(html: str, base_url: str = "") -> list[str]:
    """Absolute http(s) links of an HTML document, unique, in order."""
    from urllib.parse import urljoin

    soup = BeautifulSoup(html, "lxml")
    seen: dict[str, None] = {}
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a["href"].strip())
        if href.startswith(("http://", "https://")):
            seen.setdefault(href.split("#")[0], None)
    return list(seen)


def normalize_ws(text: str) -> str:
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def content_hash(*parts: str | None) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


_ABBREV = r"(?<!\be\.g)(?<!\bi\.e)(?<!\bv)(?<!\bvs)(?<!\bno)"
_SENT_SPLIT = re.compile(_ABBREV + r"(?<=[.!?])\s+(?=[A-ZÀ-Ý\[\(\"'«])")


def paragraphs(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"\n\s*\n|\n(?=[-*•]\s)", text) if p.strip()]


def sentences(paragraph: str) -> list[str]:
    out: list[str] = []
    for line in paragraph.split("\n"):
        out.extend(s.strip() for s in _SENT_SPLIT.split(line) if s.strip())
    return out
