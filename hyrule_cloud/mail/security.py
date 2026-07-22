from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import socket
from html.parser import HTMLParser
from urllib.parse import urlsplit

_ALLOWED_TAGS = {
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "em",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "strong",
    "ul",
}
_VOID_TAGS = {"br"}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class _Sanitizer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.output: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag not in _ALLOWED_TAGS:
            return
        rendered = ""
        if tag == "a":
            values = {name.lower(): value for name, value in attrs}
            href = (values.get("href") or "").strip()
            parsed = urlsplit(href)
            if parsed.scheme in {"http", "https", "mailto"}:
                rendered = f' href="{html.escape(href, quote=True)}" rel="noopener noreferrer"'
        self.output.append(f"<{tag}{rendered}>")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _ALLOWED_TAGS and tag not in _VOID_TAGS:
            self.output.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        self.output.append(html.escape(data))


def sanitize_html(value: str | None) -> str | None:
    if value is None:
        return None
    parser = _Sanitizer()
    parser.feed(value)
    parser.close()
    return "".join(parser.output)


async def validate_webhook_url(value: str) -> tuple[str, list[str]]:
    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("webhook URL must be an https URL without embedded credentials")
    if parsed.port not in {None, 443}:
        raise ValueError("webhook URL must use port 443")
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo,
            parsed.hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise ValueError("webhook hostname did not resolve") from exc
    addresses = sorted({str(item[4][0]) for item in infos})
    if not addresses:
        raise ValueError("webhook hostname did not resolve")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError("webhook hostname resolves to a private or special-use address")
    return parsed.geturl(), addresses
