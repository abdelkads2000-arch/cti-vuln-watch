"""Generic collectors configurable from sources.yaml (no code needed to add a source).

rss       : any RSS/Atom feed. Options: fetch_article (bool, fetch linked page, robots.txt
            respected), content_selector (CSS selector for the article body).
json_api  : any JSON API. Options:
              items_path: "data.items"          dot path to the list of items
              fields: {id:, url:, title:, content:, published:}   dot paths inside an item
              headers: {Header: "${ENV_VAR}"}   values may reference .env secrets
"""

from __future__ import annotations

import os
import re

import feedparser

from cti.collectors.base import CollectResult, Collector, ItemOut, register
from cti.collectors.common import evidence_from_text, parse_date
from cti.extraction.text import content_hash, extract_links, find_cves, html_to_text
from cti.http import RobotsDisallowed

MAX_ARTICLES_PER_RUN = 30


def _mention_kind(role: str) -> str:
    return {"vendor": "vendor_advisory", "cert": "cert_advisory"}.get(role, "mention")


@register
class RssCollector(Collector):
    type = "rss"

    def collect(self) -> CollectResult:
        r = self.http.get(self.ctx.url, conditional=True)
        if r.not_modified:
            return CollectResult(not_modified=True)
        feed = feedparser.parse(r.content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux illisible: {feed.bozo_exception}")
        seen: dict = dict(self.ctx.state.get("entries", {}))
        res = CollectResult()
        fetched = 0
        for e in feed.entries:
            link = e.get("link") or e.get("id")
            if not link:
                continue
            ext_id = e.get("id") or link
            h = content_hash(e.get("title"), e.get("summary"))
            if seen.get(ext_id) == h:
                continue
            html = e.get("content", [{}])[0].get("value") if e.get("content") else e.get("summary", "")
            text = html_to_text(html or "")
            links = extract_links(html or "", link)
            if self.ctx.config.get("fetch_article") and fetched < MAX_ARTICLES_PER_RUN:
                try:
                    page = self.http.get(link, check_robots=True, min_interval=2.0)
                    text = html_to_text(page.text, root_selector=self.ctx.config.get("content_selector"))
                    links = extract_links(page.text, link)
                    fetched += 1
                except RobotsDisallowed:
                    res.notes.append(f"robots.txt: article non récupéré {link}")
            title = e.get("title")
            cves = list(dict.fromkeys(find_cves(title) + find_cves(text) + find_cves(" ".join(links))))
            res.items.append(
                ItemOut(ext_id, link, title, text, parse_date(e.get("published") or e.get("updated")), {"entry": _jsonable(e)}, cves, links)
            )
            if cves:
                res.evidence += evidence_from_text(
                    f"{title}\n\n{text}",
                    settings=self.settings,
                    role=self.ctx.role,
                    url=link,
                    doc_cves=cves,
                    item_external_id=ext_id,
                    mention_kind=_mention_kind(self.ctx.role),
                )
            seen[ext_id] = h
        ids_in_feed = {e.get("id") or e.get("link") for e in feed.entries}
        res.new_state = {"entries": {k: v for k, v in seen.items() if k in ids_in_feed}}
        return res


def _jsonable(entry) -> dict:
    keep = ("id", "link", "title", "summary", "published", "updated", "author", "tags")
    return {k: (list(map(dict, entry[k])) if k == "tags" else entry[k]) for k in keep if k in entry}


def _dig(obj, path: str | None):
    if not path:
        return None
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit():
            obj = obj[int(part)] if int(part) < len(obj) else None
        else:
            return None
    return obj


_ENV_REF = re.compile(r"\$\{([A-Z0-9_]+)\}")


@register
class JsonApiCollector(Collector):
    type = "json_api"

    def collect(self) -> CollectResult:
        cfg = self.ctx.config
        headers = {k: _ENV_REF.sub(lambda m: os.environ.get(m.group(1), ""), str(v)) for k, v in (cfg.get("headers") or {}).items()}
        r = self.http.get(self.ctx.url, params=cfg.get("params"), headers=headers, conditional=True)
        if r.not_modified:
            return CollectResult(not_modified=True)
        items = _dig(r.json(), cfg.get("items_path")) if cfg.get("items_path") else r.json()
        if not isinstance(items, list):
            raise ValueError(f"items_path {cfg.get('items_path')!r} ne désigne pas une liste")
        f = cfg.get("fields", {})
        res = CollectResult()
        for it in items:
            url = str(_dig(it, f.get("url")) or self.ctx.url)
            ext_id = str(_dig(it, f.get("id")) or url)
            title = _dig(it, f.get("title"))
            content = _dig(it, f.get("content"))
            text = html_to_text(content) if isinstance(content, str) and "<" in content else (content or "")
            cves = list(dict.fromkeys(find_cves(str(title)) + find_cves(str(text))))
            res.items.append(ItemOut(ext_id, url, title, text, parse_date(_dig(it, f.get("published"))), it, cves))
            if cves:
                res.evidence += evidence_from_text(
                    f"{title}\n\n{text}", settings=self.settings, role=self.ctx.role, url=url, doc_cves=cves,
                    item_external_id=ext_id, mention_kind=_mention_kind(self.ctx.role),
                )
        return res
