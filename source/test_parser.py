"""Regression checks for MIME conversion and safe offline email rendering."""

import email.parser
import email.policy
import tempfile
import unittest
from email.message import EmailMessage
from email.mime.message import MIMEMessage
from pathlib import Path

from build_archive import bodies, extract_attachments, html_text, safe_filename, safe_html


class ParserTests(unittest.TestCase):
    def test_quoted_printable_charset(self):
        message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            b'Content-Type: text/plain; charset="windows-1252"\r\n'
            b'Content-Transfer-Encoding: quoted-printable\r\n\r\nCaf=E9 =97 welcome')
        self.assertEqual(bodies(message)[0], "Café — welcome")

    def test_multipart_alternatives_are_not_duplicated(self):
        m = EmailMessage()
        m.set_content("Unique plaintext")
        m.add_alternative("<p>Unique plaintext</p>", subtype="html")
        plain, rich = bodies(m)
        self.assertEqual(plain, "Unique plaintext")
        self.assertIn("Unique plaintext", rich)

    def test_plaintext_is_preferred_even_when_html_is_first(self):
        m = EmailMessage()
        m.set_content("<p>HTML version</p>", subtype="html")
        m.add_alternative("Plaintext version")
        self.assertEqual(bodies(m)[0], "Plaintext version")

    def test_html_only_messages_are_searchable(self):
        m = EmailMessage()
        m.set_content('<style>secret</style><p>Hello &amp; welcome</p><a href="https://example.com/destination">Visit</a>', subtype="html")
        plain, _ = bodies(m)
        self.assertIn("Hello & welcome", plain)
        self.assertIn("https://example.com/destination", plain)
        self.assertNotIn("secret", plain)

    def test_forwarded_message_and_text_attachment(self):
        outer, forwarded = EmailMessage(), EmailMessage()
        outer.set_content("Outer body")
        forwarded["From"], forwarded["Subject"] = "Sender <sender@example.com>", "Forwarded subject"
        forwarded.set_content("Searchable forwarded body")
        outer.make_mixed()
        outer.attach(MIMEMessage(forwarded))
        outer.add_attachment("This is an attachment, not the email body", subtype="plain", filename="note.txt")
        plain, _ = bodies(outer)
        self.assertEqual(plain.count("Searchable forwarded body"), 1)
        self.assertIn("Forwarded subject", plain)
        self.assertNotIn("This is an attachment", plain)
        with tempfile.TemporaryDirectory() as directory:
            attachments = extract_attachments(outer, "test", Path(directory))
            self.assertEqual(len(attachments), 2)
            self.assertEqual(attachments[0]["name"], "forwarded-message.eml")

    def test_safe_html_removes_active_content_and_remote_images(self):
        rich = safe_html('<script>alert(1)</script><iframe src="https://tracker.example"></iframe><img src="https://tracker.example/pixel" alt="Photo"><a href="javascript:alert(1)" onclick="bad()">Click</a><p style="color:blue;background-image:url(https://tracker.example)">Body</p>')
        self.assertNotIn("<script", rich)
        self.assertNotIn("<iframe", rich)
        self.assertNotIn("<img", rich)
        self.assertNotIn("tracker.example", rich)
        self.assertNotIn("javascript:", rich)
        self.assertNotIn("onclick", rich)
        self.assertIn("color:blue", rich)
        self.assertIn("[Photo]", rich)

    def test_malformed_html_attributes(self):
        value = '<img alt><a href>Test</a><p style>Still here</p><a href="https://[invalid">Bad URL</a>'
        self.assertIn("Still here", safe_html(value))
        self.assertIn("Test", html_text(value))

    def test_attachment_names_cannot_traverse_paths(self):
        self.assertEqual(safe_filename("../../file.pdf"), "file.pdf")
        self.assertEqual(safe_filename("..\\..\\file.pdf"), "file.pdf")
        self.assertLessEqual(len(safe_filename("é" * 500 + ".pdf").encode("utf-8")), 180)
        m = EmailMessage()
        m.set_content("Body")
        m.add_attachment(b"unchanged bytes", maintype="application", subtype="octet-stream", filename="../../payload.bin")
        with tempfile.TemporaryDirectory() as directory:
            attachments = extract_attachments(m, "test", Path(directory))
            target = Path(directory) / attachments[0]["path"]
            self.assertEqual(target.read_bytes(), b"unchanged bytes")
            self.assertTrue(target.resolve().is_relative_to(Path(directory).resolve()))


if __name__ == "__main__":
    unittest.main()
