"""
Safe public URL HTTP client for DigitalShield Provenance Subsystem.

SECURITY & SSRF CONTROLS:
- Strictly permits http:// and https:// schemes only.
- Blocks localhost, loopback, private IPv4/IPv6, link-local, and reserved addresses.
- Enforces strict socket timeouts and response byte limits.
- Validates redirected URLs against SSRF filters before following.
- Stores zero cookies, credentials, or session state.
"""

import html
import ipaddress
import re
import socket
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple


class SafePublicClient:
    """
    SSRF-safe client for fetching public HTTP/HTTPS resources and extracting metadata.
    """

    def __init__(self, timeout: int = 10, max_bytes: int = 5 * 1024 * 1024):
        self.timeout = timeout
        self.max_bytes = max_bytes

    @staticmethod
    def validate_url(url: str) -> str:
        """
        Validate URL for SSRF safety and scheme constraints.
        Raises ValueError if URL is invalid or targets private/internal network addresses.
        """
        if not url or not isinstance(url, str):
            raise ValueError("Invalid URL: URL must be a non-empty string.")

        parsed = urllib.parse.urlparse(url.strip())
        scheme = parsed.scheme.lower()

        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme '{scheme}'. Only http:// and https:// are permitted.")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid URL: Missing hostname.")

        hostname_lower = hostname.lower()

        # Direct string checks for obvious localhost / internal targets
        if hostname_lower in ("localhost", "localhost.localdomain", "127.0.0.1", "::1", "0.0.0.0"):
            raise ValueError(f"Access denied: Target '{hostname}' is a loopback/internal address.")

        # Attempt IP resolution to detect private/internal networks behind hostnames
        port = parsed.port if parsed.port else (443 if scheme == "https" else 80)
        try:
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise ValueError(f"Failed to resolve host '{hostname}': {e}")

        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if (
                    ip_obj.is_private
                    or ip_obj.is_loopback
                    or ip_obj.is_link_local
                    or ip_obj.is_reserved
                    or ip_obj.is_multicast
                ):
                    raise ValueError(
                        f"Access denied: Target '{hostname}' ({ip_str}) resolves to a private or internal network address."
                    )
            except ValueError as ve:
                if "Access denied" in str(ve):
                    raise
                pass

        return url.strip()

    def fetch_public_url(
        self,
        url: str,
        max_redirects: int = 3
    ) -> Tuple[int, Dict[str, str], bytes]:
        """
        Safely fetch public URL content with size limit, timeout, and redirect validation.
        Returns (status_code, headers_dict, content_bytes).
        """
        current_url = self.validate_url(url)
        redirect_count = 0

        while redirect_count <= max_redirects:
            parsed = urllib.parse.urlparse(current_url)
            req = urllib.request.Request(
                current_url,
                headers={"User-Agent": "DigitalShield-ForensicProvenance/1.0"}
            )

            try:
                # Custom opener to prevent automatic unvalidated redirects
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None

                opener = urllib.request.build_opener(NoRedirectHandler)
                with opener.open(req, timeout=self.timeout) as response:
                    status_code = response.status
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    # Read up to max_bytes + 1 to detect oversized content
                    content = response.read(self.max_bytes + 1)
                    if len(content) > self.max_bytes:
                        raise ValueError(f"Oversized response: Content exceeds safe limit of {self.max_bytes} bytes.")

                    return status_code, headers, content

            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    redirect_url = e.headers.get("Location")
                    if not redirect_url:
                        raise ValueError(f"HTTP Redirect {e.code} received without Location header.")
                    
                    # Handle relative redirect URLs
                    redirect_url = urllib.parse.urljoin(current_url, redirect_url)
                    current_url = self.validate_url(redirect_url)
                    redirect_count += 1
                    continue
                else:
                    headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                    content = e.read(self.max_bytes) if hasattr(e, "read") else b""
                    return e.code, headers, content

            except Exception as ex:
                if "Access denied" in str(ex) or "Oversized response" in str(ex):
                    raise
                raise ValueError(f"Failed to fetch public URL '{url}': {ex}")

        raise ValueError(f"Too many redirects (exceeded limit of {max_redirects}).")

    @staticmethod
    def extract_public_metadata(content: bytes, content_type: str = "") -> Dict[str, Optional[str]]:
        """
        Extract visible title from public HTML bytes.
        """
        metadata: Dict[str, Optional[str]] = {
            "source_title": None,
        }

        if not content:
            return metadata

        if "text/html" in content_type.lower() or content.strip().startswith(b"<"):
            try:
                html_text = content.decode("utf-8", errors="ignore")
                match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
                if match:
                    raw_title = match.group(1).strip()
                    clean_title = html.unescape(re.sub(r"\s+", " ", raw_title))
                    metadata["source_title"] = clean_title[:200]
            except Exception:
                pass

        return metadata
