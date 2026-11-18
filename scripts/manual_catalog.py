"""Read the two APKs offered by the public TBCC installation page."""

import json
import re
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.request import HTTPRedirectHandler, Request, build_opener


CATALOG_URL = "https://vpn.tbcc.com/setup/tbcc"
MAX_HTML_BYTES = 512 * 1024
APK_URL = re.compile(
    r"https://updates\.tbcc\.com/downloads/android/stable/"
    r"([1-9][0-9]{0,9})/(arm64-v8a|universal)\.apk"
)
INERT = {"script", "style", "template", "noscript", "iframe", "textarea", "title"}


@dataclass(frozen=True)
class ManualCatalog:
    code: int
    arm64_sha256: str
    urls: dict[str, str]


class _CatalogParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inert = []
        self.links = {}
        self.sha_section = False
        self.sha_text = None
        self.digest = None

    def handle_starttag(self, tag, attrs):
        if tag in INERT:
            self.inert.append(tag)
        if self.inert:
            return
        attributes = dict(attrs)
        if tag == "a":
            href = attributes.get("href") or ""
            if "download" in attributes or "/downloads/android/" in href or href.endswith(".apk"):
                match = APK_URL.fullmatch(href)
                if not match or sum(key == "href" for key, _ in attrs) != 1:
                    raise ValueError("Unexpected APK download target")
                code, abi = match.groups()
                if not 14 <= int(code) <= 2_100_000_000 or abi in self.links:
                    raise ValueError("Unsupported or duplicate APK download")
                self.links[abi] = (int(code), href)
        if tag == "p":
            if self.sha_section:
                raise ValueError("Malformed checksum paragraph")
            if "tbcc-apk-hash" in (attributes.get("class") or "").split():
                if self.digest is not None:
                    raise ValueError("Duplicate checksum paragraph")
                self.sha_section = True
        if self.sha_text is not None:
            raise ValueError("Unexpected markup in APK checksum")
        if tag == "code" and self.sha_section:
            if self.digest is not None:
                raise ValueError("Duplicate APK checksum")
            self.sha_text = []

    def handle_data(self, value):
        if not self.inert and self.sha_text is not None:
            self.sha_text.append(value)

    def handle_endtag(self, tag):
        if self.inert:
            if tag == self.inert[-1]:
                self.inert.pop()
            return
        if tag == "code" and self.sha_text is not None:
            value = "".join(self.sha_text).strip()
            if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                raise ValueError("Invalid ARM64 checksum")
            self.digest = value.lower()
            self.sha_text = None
        if tag == "p" and self.sha_section:
            if self.sha_text is not None or self.digest is None:
                raise ValueError("Incomplete checksum paragraph")
            self.sha_section = False


def parse_manual_catalog(html: bytes) -> ManualCatalog:
    if len(html) > MAX_HTML_BYTES:
        raise ValueError("Installation page is too large")
    parser = _CatalogParser()
    parser.feed(html.decode("utf-8"))
    parser.close()
    if parser.sha_section or not parser.digest or set(parser.links) != {"arm64-v8a", "universal"}:
        raise ValueError("Installation page is missing its two APKs or ARM64 checksum")
    codes = {code for code, _ in parser.links.values()}
    if len(codes) != 1:
        raise ValueError("APK links refer to different version codes")
    return ManualCatalog(codes.pop(), parser.digest, {abi: url for abi, (_, url) in parser.links.items()})


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Installation page redirected away from its canonical URL")


def fetch_manual_catalog() -> ManualCatalog:
    request = Request(CATALOG_URL, headers={"Accept": "text/html", "Accept-Encoding": "identity"})
    with build_opener(_NoRedirect()).open(request, timeout=15) as response:
        if response.status != 200 or response.geturl() != CATALOG_URL or response.headers.get_content_type() != "text/html":
            raise ValueError("Unexpected response from installation page")
        return parse_manual_catalog(response.read(MAX_HTML_BYTES + 1))


if __name__ == "__main__":
    print(json.dumps(asdict(fetch_manual_catalog()), sort_keys=True))
