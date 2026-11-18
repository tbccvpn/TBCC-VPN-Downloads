import unittest
from email.message import Message
from unittest.mock import patch
from urllib.request import Request

from scripts import manual_catalog as catalog


BASE = "https://updates.tbcc.com/downloads/android/stable/14/"
ARM = BASE + "arm64-v8a.apk"
UNIVERSAL = BASE + "universal.apk"
SHA = "b" * 64


def link(url):
    return f'<a download href="{url}">APK</a>'


def page(arm=ARM, universal=UNIVERSAL, sha=SHA):
    return link(arm) + link(universal) + f'<p class="small tbcc-apk-hash">SHA-256: <code>{sha}</code></p>'


class ManualCatalogTests(unittest.TestCase):
    def test_two_links_and_scoped_checksum(self):
        html = page().replace("APK</a>", "下载</a>").replace("SHA-256:", "文件校验")
        result = catalog.parse_manual_catalog(('<a href="/setup">help</a><code>unrelated</code>' + html).encode())
        self.assertEqual(result, catalog.ManualCatalog(14, SHA, {"arm64-v8a": ARM, "universal": UNIVERSAL}))

    def test_unapproved_or_ambiguous_document(self):
        valid = page()
        bad_pages = [
            page(universal=UNIVERSAL.replace("/14/", "/15/")),
            valid.replace("/14/", "/13/"),
            valid.replace("/14/", "/020/"),
            page(arm=ARM.replace("stable", "development")),
            page(universal=UNIVERSAL.replace("updates.tbcc.com", "mirror.invalid")),
            page(arm=ARM.replace("https:", "http:")),
            page(arm=ARM + "?preview=true"),
            page(universal=UNIVERSAL.replace("/14/", "/14/../15/")),
            valid + link(ARM),
            valid.replace('href="', 'href="https://example.invalid" href="', 1),
            valid.replace(link(UNIVERSAL), ""),
            page(sha="f" * 63),
            valid.replace("tbcc-apk-hash", "old-tbcc-apk-hash"),
            valid.replace("</code>", f"</code><code>{SHA}</code>"),
            valid.replace("<code>", "").replace("</code>", ""),
            valid.replace("</code>", "").replace("</p>", ""),
            valid + f'<p class="tbcc-apk-hash"><code>{SHA}</code></p>',
            f'<script>{valid}</script><template>{valid}</template><noscript>{valid}</noscript>',
            valid.replace(link(ARM), f"<!--{link(ARM)}-->"),
            valid.replace(link(ARM), f'<script type="application/json">"{ARM}"</script>'),
            valid.replace(link(ARM), ARM),
        ]
        for index, html in enumerate(bad_pages):
            with self.subTest(case=index), self.assertRaises(ValueError):
                catalog.parse_manual_catalog(html.encode())

    def test_page_size_limit(self):
        with self.assertRaises(ValueError):
            catalog.parse_manual_catalog(b" " * (catalog.MAX_HTML_BYTES + 1))

    def test_fetch_uses_only_fixed_public_page_and_bounded_read(self):
        with patch.object(catalog, "build_opener") as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.geturl.return_value = catalog.CATALOG_URL
            response.headers = Message()
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            response.read.return_value = page().encode()
            self.assertEqual(catalog.fetch_manual_catalog().code, 14)
            req, = factory.return_value.open.call_args.args
            self.assertEqual(req.full_url, catalog.CATALOG_URL)
            self.assertFalse(req.has_header("Authorization"))
            response.read.assert_called_once_with(catalog.MAX_HTML_BYTES + 1)

    def test_redirect_is_refused(self):
        with self.assertRaises(ValueError):
            catalog._NoRedirect().redirect_request(Request(catalog.CATALOG_URL), None, 302, "", {}, "https://other.invalid/")


if __name__ == "__main__":
    unittest.main()
