#!/usr/bin/env python3
"""Build an offline, searchable email archive using only Python's standard library."""

from __future__ import annotations

import argparse
import csv
import email.encoders
import email.parser
import email.policy
import hashlib
import html
import json
import mailbox
import mimetypes
import re
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urlsplit


POLICY = email.policy.default
BLOCKS = {"address", "article", "blockquote", "div", "dl", "dt", "dd", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "li", "main", "ol", "p", "pre", "section", "table", "tr", "ul"}
SKIP = {"script", "style", "head", "title", "noscript", "template", "iframe", "object", "svg", "math"}
ALLOWED = BLOCKS | {"a", "b", "br", "caption", "center", "code", "col", "colgroup", "em", "font", "hr", "i", "img", "s", "small", "span", "strike", "strong", "sub", "sup", "tbody", "td", "th", "thead", "u", "wbr"}
VOID = {"br", "hr", "img", "col", "wbr"}
SAFE_STYLE = {"color", "background-color", "font-size", "font-family", "font-weight", "font-style", "text-align", "text-decoration", "line-height", "border", "border-top", "border-bottom", "border-left", "border-right", "border-collapse", "padding", "padding-top", "padding-bottom", "padding-left", "padding-right", "margin", "margin-top", "margin-bottom", "margin-left", "margin-right", "vertical-align", "white-space", "list-style-type"}


def clean(value: str) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value).replace("\r\n", "\n").replace("\r", "\n")


def redact_unsubscribe_tokens(value: str) -> str:
    """Remove personal unsubscribe and dynamic-email link tokens before export."""
    value = re.sub(
        r"(https://app\.scoir\.com/not-interested\?[^\s<>\"']*?(?:&|&amp;)sToken=)[0-9a-fA-F-]{36}(?![0-9a-fA-F-])",
        r"\g<1>REDACTED",
        value,
    )
    return re.sub(
        r"(\bdynamicEmailToken=)[^\s<>\"'&]+",
        r"\g<1>REDACTED",
        value,
    )


def redact_attached_email(data: bytes) -> bytes:
    """Redact link tokens in decoded MIME parts, including AMP email content."""
    message = email.parser.BytesParser(policy=POLICY).parsebytes(data)
    changed = False
    for part in message.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        original = decode_part(part)
        redacted = redact_unsubscribe_tokens(original)
        if redacted == original:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            encoded = redacted.encode(charset)
        except (LookupError, UnicodeError):
            encoded = redacted.encode("utf-8")
            part.set_param("charset", "utf-8")
        if "Content-Transfer-Encoding" in part:
            del part["Content-Transfer-Encoding"]
        part.set_payload(encoded)
        email.encoders.encode_quopri(part)
        changed = True
    return message.as_bytes(policy=POLICY) if changed else data


def header(message, name: str) -> str:
    return " ".join(clean(str(message.get(name, ""))).splitlines()).strip()


def decode_part(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        value = part.get_payload()
        return clean(value) if isinstance(value, str) else ""
    for charset in dict.fromkeys([part.get_content_charset(), "utf-8", "windows-1252"]):
        if not charset:
            continue
        try:
            return clean(payload.decode(charset))
        except (LookupError, UnicodeError):
            continue
    return clean(payload.decode("utf-8", errors="replace"))


class TextHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skipped = []

    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self.skipped.append(tag)
        if self.skipped:
            return
        attrs = dict(attrs)
        if tag in BLOCKS or tag in {"br", "hr"}:
            self.parts.append("\n")
        if tag == "li":
            self.parts.append("• ")
        if tag in {"td", "th"}:
            self.parts.append("\t")
        if tag == "img" and attrs.get("alt"):
            self.parts.append(attrs["alt"])
        if tag == "a" and (attrs.get("href") or "").startswith(("https://", "http://", "mailto:")):
            # Keep link destinations searchable even when only a title is visible.
            self.parts.append(" <" + attrs["href"] + "> ")

    def handle_endtag(self, tag):
        if self.skipped:
            if tag == self.skipped[-1]:
                self.skipped.pop()
            return
        if tag in BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skipped:
            self.parts.append(data)

    def value(self):
        result = clean("".join(self.parts)).replace("\xa0", " ")
        result = re.sub(r"[ \t]+\n", "\n", result)
        return re.sub(r"\n{4,}", "\n\n\n", result).strip()


def html_text(value):
    parser = TextHTML()
    parser.feed(value)
    return parser.value()


class SafeHTML(HTMLParser):
    """Keep email formatting, but strip active content and remote resources."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skipped = []

    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self.skipped.append(tag)
        if self.skipped or tag not in ALLOWED:
            return
        attrs = dict(attrs)
        safe = []
        if tag == "img":
            # Inline images remain available as local attachments. No remote requests.
            alt = (attrs.get("alt") or "").strip()
            if alt:
                self.parts.append('<span class="image-label">[' + html.escape(alt) + "]</span>")
            return
        if tag == "a":
            href = (attrs.get("href") or "").strip()
            try:
                allowed_link = urlsplit(href).scheme.lower() in {"http", "https", "mailto"}
            except ValueError:
                allowed_link = False
            if allowed_link:
                safe.extend([("href", href), ("target", "_blank"), ("rel", "noopener noreferrer")])
        for name in ("title", "colspan", "rowspan", "align", "dir"):
            value = attrs.get(name)
            if value:
                safe.append((name, value))
        styles = []
        for declaration in (attrs.get("style") or "").split(";"):
            if ":" not in declaration:
                continue
            name, value = declaration.split(":", 1)
            name, value = name.strip().lower(), value.strip()
            if name in SAFE_STYLE and not re.search(r"url|expression|[\\<>@]", value, re.I):
                styles.append(name + ":" + value)
        if styles:
            safe.append(("style", ";".join(styles)))
        self.parts.append("<" + tag + "".join(' ' + k + '="' + html.escape(v, quote=True) + '"' for k, v in safe) + ">")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.skipped:
            if tag == self.skipped[-1]:
                self.skipped.pop()
            return
        if tag in ALLOWED and tag not in VOID:
            self.parts.append("</" + tag + ">")

    def handle_data(self, data):
        if not self.skipped:
            self.parts.append(html.escape(data))


def safe_html(value):
    parser = SafeHTML()
    parser.feed(value)
    return "".join(parser.parts)


def bodies(part, nested=False):
    """Choose one MIME alternative and include forwarded message contents once."""
    kind = part.get_content_type()
    if kind == "message/rfc822":
        chunks = []
        for embedded in part.get_payload() if isinstance(part.get_payload(), list) else []:
            plain, _ = bodies(embedded, nested=True)
            details = "\n".join(f"{name}: {header(embedded, name)}" for name in ("From", "To", "Date", "Subject"))
            chunks.append("---------- Forwarded message ----------\n" + details + "\n\n" + plain)
        return "\n\n".join(chunks), ""
    if part.get_content_disposition() == "attachment" or part.get_filename():
        return "", ""
    if part.is_multipart():
        parts = list(part.iter_parts())
        children = [bodies(child, nested=nested) for child in parts]
        if part.get_content_subtype() == "alternative":
            plain = next((p for child, (p, rich) in zip(parts, children) if child.get_content_type() == "text/plain" and p.strip()), "")
            plain = plain or next((p for p, rich in children if p.strip()), "")
            rich = next((h for p, h in reversed(children) if h.strip()), "")
            return plain or html_text(rich), rich
        plains = [p for p, h in children if p.strip()]
        rich = "<hr>".join(h for p, h in children if h.strip())
        return "\n\n".join(plains), rich
    if kind == "text/plain":
        return decode_part(part).strip(), ""
    if kind == "text/html":
        rich = decode_part(part)
        return html_text(rich), rich
    return "", ""


def safe_filename(name):
    name = unicodedata.normalize("NFC", name).replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[\x00-\x1f<>:\"/\\|?*]", "_", name).strip(". ")
    if not name:
        name = "attachment"
    # Keep file paths comfortably below OS filename byte limits.
    suffix = Path(name).suffix[:20]
    stem = name[:-len(suffix)] if suffix else name
    while len((stem + suffix).encode("utf-8")) > 180:
        stem = stem[:-1]
    return stem + suffix


def extract_attachments(message, message_id, outdir):
    attachments = []
    for part in message.walk():
        kind = part.get_content_type()
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment" and kind != "message/rfc822":
            continue
        if kind == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list):
                data = b"\n\n".join(item.as_bytes(policy=POLICY) for item in payload)
            else:
                data = part.get_payload(decode=True) or b""
            filename = filename or "forwarded-message.eml"
        else:
            if part.is_multipart():
                continue
            data = part.get_payload(decode=True)
            if data is None:
                continue
            filename = filename or ("attachment" + (mimetypes.guess_extension(kind) or ".bin"))
        if kind == "message/rfc822" or str(filename).lower().endswith(".eml"):
            data = redact_attached_email(data)
        filename = safe_filename(str(filename))
        relative = Path("attachments") / message_id / (f"{len(attachments) + 1:02d}-" + filename)
        destination = outdir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        attachments.append({"name": filename, "path": quote(relative.as_posix(), safe="/"), "size": len(data), "type": kind, "inline": part.get_content_disposition() == "inline", "sha256": hashlib.sha256(data).hexdigest()})
    return attachments


def format_message(message):
    lines = [message["subject"], f'From: {message["fromRaw"]}', f'To: {message["to"]}']
    for key, name in (("cc", "Cc"), ("bcc", "Bcc"), ("dateRaw", "Date")):
        if message.get(key):
            lines.append(f"{name}: {message[key]}")
    if message["labels"]:
        lines.append("Labels: " + ", ".join(message["labels"]))
    if message["messageId"]:
        lines.append("Message-ID: " + message["messageId"])
    lines.extend(["", message["body"] or "[No text body]"])
    if message["attachments"]:
        lines.extend(["", "Attachments:"])
        for item in message["attachments"]:
            lines.append(f'- {item["name"]} ({item["size"]:,} bytes) — {item["path"]}')
    return "\n".join(lines)


def build(source, output):
    output.mkdir(parents=True, exist_ok=True)
    box = mailbox.mbox(source, factory=lambda f: email.parser.BytesParser(policy=POLICY).parse(f), create=False)
    messages, warnings = [], []
    for index, message in enumerate(box, 1):
        mid = f"mail-{index:05d}"
        labels = []
        for value in message.get_all("X-Gmail-Labels", []):
            labels.extend(label.strip() for label in next(csv.reader([str(value)])) if label.strip())
        labels = list(dict.fromkeys(labels))
        date_raw = header(message, "Date")
        try:
            date = parsedate_to_datetime(date_raw)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            timestamp, date_iso = int(date.timestamp() * 1000), date.isoformat()
        except (ValueError, TypeError, OverflowError):
            timestamp, date_iso = None, ""
            warnings.append(f"{mid}: Date could not be parsed; original header retained.")
        from_raw = header(message, "From")
        addresses = getaddresses([from_raw], strict=False)
        name, address = addresses[0] if addresses else (from_raw or "Unknown sender", "")
        plain, rich = bodies(message)
        plain, rich = redact_unsubscribe_tokens(plain), redact_unsubscribe_tokens(rich)
        attachments = extract_attachments(message, mid, output)
        item = {"id": mid, "fromName": name or address or "Unknown sender", "fromEmail": address.lower(), "fromRaw": from_raw,
                "to": header(message, "To"), "cc": header(message, "Cc"), "bcc": header(message, "Bcc"),
                "subject": header(message, "Subject") or "(No subject)", "dateRaw": date_raw,
                "timestamp": timestamp, "dateISO": date_iso, "labels": labels,
                "read": "Unread" not in labels, "starred": "Starred" in labels,
                "messageId": header(message, "Message-ID"), "body": plain,
                "html": safe_html(rich) if rich else "", "htmlText": html_text(rich) if rich else "",
                "attachments": attachments, "snippet": " ".join(plain.split())[:200]}
        messages.append(item)
        if index % 100 == 0:
            print(f"Parsed {index} messages…", flush=True)
    box.close()
    messages.sort(key=lambda m: (m["timestamp"] is not None, m["timestamp"] or 0, m["id"]), reverse=True)
    labels = Counter(label for m in messages for label in m["labels"])
    dates = [m["dateISO"][:10] for m in messages if m["dateISO"]]
    attachment_count = sum(len(m["attachments"]) for m in messages)
    manifest = {"source": str(source.name), "messageCount": len(messages),
                "senderCount": len({m["fromEmail"] or m["fromRaw"] for m in messages}),
                "attachmentCount": attachment_count,
                "attachmentBytes": sum(a["size"] for m in messages for a in m["attachments"]),
                "dateRange": [min(dates), max(dates)] if dates else [], "labels": dict(labels), "warnings": warnings}
    title = ["ALL EMAILS — COMBINED ARCHIVE", "=" * 80, f'Source: {source.name}',
             f'Messages: {len(messages):,}', f'Attachments: {attachment_count:,}',
             "Order: newest first. Original date headers and time zones are preserved.",
             "Attachment files are in the attachments folder; their contents are not transcribed.", ""]
    with (output / "All Emails.txt").open("w", encoding="utf-8") as doc:
        doc.write("\n".join(title))
        for number, message in enumerate(messages, 1):
            doc.write(f'\n{"=" * 80}\nEMAIL {number} OF {len(messages)} | {message["id"]}\n{"=" * 80}\n')
            doc.write(format_message(message) + "\n")
    archive = {"meta": manifest, "messages": messages}
    serialized = json.dumps(archive, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    template = (Path(__file__).parent / "inbox_template.html").read_text(encoding="utf-8")
    assert template.count("__ARCHIVE_DATA__") == 1
    (output / "index.html").write_text(template.replace("__ARCHIVE_DATA__", serialized), encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output / "README.txt").write_text(
        "YOUR EMAIL ARCHIVE\n\n"
        "Open index.html in your browser to browse and search your mail.\n"
        "No installation, server, account, or internet connection is needed.\n\n"
        f"Contains {len(messages):,} emails and {attachment_count:,} attachment files.\n"
        "All Emails.txt combines all message headers and text, newest first.\n"
        "Forwarded email text is included. Binary attachment contents are not transcribed.\n"
        "Keep the attachments folder next to index.html for downloads to work.\n\n"
        "Search matches full message text, subjects, senders, recipients, labels,\n"
        "and attachment filenames. Separate words are combined (all must match);\n"
        'put an exact phrase in double quotes. Searches ignore case and accents.\n'
        "Type a sender name or email in the sender box to filter messages;\n"
        "the dropdown shows the first six matching senders. Select a name for\n"
        "an exact sender match. Use the arrow keys and Enter, or click a name.\n"
        "Sender, sidebar label, and date filters can be combined.\n"
        "Click Export beside the filters to save every email in the current view\n"
        "as one text document, including results beyond the visible page.\n"
        "The date filters use the calendar date in each original message header.\n\n"
        "Use the sidebar to select All mail, Inbox, Sent, Archived, Trash, or a label.\n"
        "Read status and stars are saved in this browser when local storage is available.\n"
        "They only affect this local copy. The original MBOX is unchanged.\n"
        "Text view shows search highlights. Formatted view keeps safe email formatting;\n"
        "remote images and active email content are blocked. Inline images are files.\n"
        "Your mail stays on your computer; the page has no external dependencies.\n\n"
        "Keyboard: / or Cmd/Ctrl+K to search; J/K for next/previous email;\n"
        "Escape to leave a field or close a message on a small screen.\n\n"
        "To rebuild from the original MBOX:\n"
        '  python3 "source/build_archive.py"\n', encoding="utf-8")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mbox", type=Path, default=root.parent / "Mail" / "All mail Including Spam and Trash.mbox")
    parser.add_argument("--output", type=Path, default=root)
    args = parser.parse_args()
    build(args.mbox.resolve(), args.output.resolve())
