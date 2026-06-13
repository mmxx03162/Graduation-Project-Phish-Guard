from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

from django.core.management import CommandError
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from api.models import BlacklistedURL


OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


def _normalize_url(raw_url: str) -> str | None:
    """
    Normalize URL for better matching across sources.

    - ensure scheme (default https)
    - lowercase hostname
    - drop fragments
    - keep path/query (they can matter for phishing URLs)
    - remove trailing slash (except root '/')
    """
    if not raw_url:
        return None

    raw_url = raw_url.strip()
    if not raw_url:
        return None

    with_scheme = raw_url if "://" in raw_url else f"https://{raw_url}"
    try:
        p = urlparse(with_scheme)
        hostname = (p.hostname or "").lower()
        if not hostname:
            return None

        scheme = (p.scheme or "https").lower()
        netloc = hostname if p.port is None else f"{hostname}:{p.port}"
        path = p.path or "/"

        normalized = urlunparse((scheme, netloc, path, "", p.query, ""))
        if normalized.endswith("/") and normalized != f"{scheme}://{netloc}/":
            normalized = normalized.rstrip("/")

        return normalized
    except Exception:
        return None


def _fetch_text_lines(url: str, timeout_s: int = 20) -> list[str]:
    req = Request(
        url,
        headers={
            "User-Agent": "phish-guard/1.0 (OpenPhish feed fetcher)",
            "Accept": "text/plain,*/*",
        },
        method="GET",
    )
    with urlopen(req, timeout=timeout_s) as resp:
        content_type = (resp.headers.get("Content-Type") or "").lower()
        raw = resp.read()
    # OpenPhish feed should be plain text. If we got HTML, we are likely blocked/redirected.
    if content_type and "text/plain" not in content_type:
        sample = raw[:300].decode("utf-8", errors="replace")
        raise CommandError(
            "OpenPhish feed did not return text/plain. "
            f"Content-Type={content_type!r}. Sample={sample!r}"
        )
    text = raw.decode("utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]


@dataclass(frozen=True)
class FeedEntry:
    url: str


def _parse_openphish_feed(lines: Iterable[str]) -> list[FeedEntry]:
    # OpenPhish feed.txt is a simple newline-separated list of URLs.
    entries: list[FeedEntry] = []
    for line in lines:
        if line.startswith("#"):
            continue
        # Guardrails: if the response is HTML or contains whitespace, skip it.
        if "<" in line or ">" in line or " " in line or "\t" in line:
            continue
        norm = _normalize_url(line)
        if norm:
            entries.append(FeedEntry(url=norm))
    return entries


class Command(BaseCommand):
    help = "Fetch latest URLs from OpenPhish feed and update database blacklist."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=300,
            help="How many of the latest URLs to take from the feed (default: 300).",
        )
        parser.add_argument(
            "--feed-url",
            type=str,
            default=OPENPHISH_FEED_URL,
            help="Override OpenPhish feed URL (default: https://openphish.com/feed.txt).",
        )
        parser.add_argument(
            "--replace",
            action="store_true",
            default=True,
            help="Replace current OpenPhish entries with the latest batch (default: true).",
        )
        parser.add_argument(
            "--no-replace",
            action="store_false",
            dest="replace",
            help="Do not delete old OpenPhish entries; only insert new ones.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=20,
            help="HTTP timeout in seconds (default: 20).",
        )

    def handle(self, *args, **options):
        limit: int = max(1, int(options["limit"]))
        feed_url: str = str(options["feed_url"])
        timeout_s: int = max(1, int(options["timeout"]))
        replace: bool = bool(options["replace"])

        self.stdout.write(f"Fetching OpenPhish feed: {feed_url}")
        try:
            lines = _fetch_text_lines(feed_url, timeout_s=timeout_s)
        except CommandError:
            raise
        except Exception as e:
            raise CommandError(f"Failed to fetch OpenPhish feed: {e}") from e
        entries = _parse_openphish_feed(lines)

        if not entries:
            raise CommandError(
                "Feed returned no usable URLs. "
                "If this started happening recently, OpenPhish may be blocking unauthenticated requests."
            )

        # OpenPhish typically lists newest first; we treat the top as "latest".
        latest = entries[:limit]

        urls = []
        seen: set[str] = set()
        for e in latest:
            if e.url not in seen:
                seen.add(e.url)
                urls.append(e.url)

        now = timezone.now()
        to_create = [BlacklistedURL(url=u, source="OpenPhish", date_added=now) for u in urls]

        with transaction.atomic():
            before_total = BlacklistedURL.objects.count()
            before_source = BlacklistedURL.objects.filter(source="OpenPhish").count()

            if replace:
                BlacklistedURL.objects.filter(source="OpenPhish").delete()

            BlacklistedURL.objects.bulk_create(to_create, ignore_conflicts=True)

            after_total = BlacklistedURL.objects.count()
            after_source = BlacklistedURL.objects.filter(source="OpenPhish").count()

        inserted_estimate = max(0, after_total - before_total)
        action = "replaced" if replace else "updated"
        self.stdout.write(
            self.style.SUCCESS(
                f"OpenPhish blacklist {action}: {after_source} URL(s) stored (inserted ~{inserted_estimate})."
            )
        )
