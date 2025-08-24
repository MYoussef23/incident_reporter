# obfuscate_data_cli.py
# CLI for obfuscating emails/UPNs, IPv4s, hostnames, and domains in HTML **and JSON**.
# Backwards compatible with your original HTML-only usage.
#
# Examples at bottom.

import re, hashlib, ipaddress, sys, json
from pathlib import Path
from typing import Iterable, List, Optional, Any, Set
from bs4 import BeautifulSoup

# ---------- Core regex/utility ----------
EMAIL_RE   = re.compile(r'\b([A-Z0-9._%+\-]+)@([A-Z0-9.\-]+\.[A-Z]{2,})\b', re.IGNORECASE)
IPV4_RE    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b')
FQDN_RE    = re.compile(r'\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)\b', re.IGNORECASE)
MACHINE_RE = re.compile(r'\b([A-Z0-9][A-Z0-9\-_]{7,}\$?)\b')  # e.g., CATPRDDSP101

def _digest(token: str, salt: str, n: int = 6) -> str:
    return hashlib.sha256((salt + "|" + token).encode()).hexdigest()[:n]

def _map_token(token: str, prefix: str, salt: str) -> str:
    return f"{prefix}-{_digest(token, salt)}"

def _pseudonymize_ip(ip: str, salt: str, map_private: bool = True) -> str:
    """Map any IPv4 to 10.x.y.z deterministically. If map_private=False, keep RFC1918 as-is."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if (not map_private) and ip_obj.is_private:
        return ip
    h = hashlib.sha256((salt + "|" + ip).encode()).digest()
    a, b, c = h[0], h[1], h[2]
    return f"10.{a}.{b}.{c}"

def _scrub_text(
    text: str,
    *,
    salt: str,
    map_private_ips: bool,
    keep_real_domain_in_emails: bool,
    mask_email_local_only: bool,
) -> str:
    # Emails first
    def repl_email(m):
        user, domain = m.group(1), m.group(2)
        dom_low = domain.lower()
        if keep_real_domain_in_emails:
            return f"{_map_token(user, 'USER', salt)}@{dom_low}"
        if mask_email_local_only:
            masked = (user[0] + "***") if user else "user"
            return f"{masked}@{dom_low}"
        return f"{_map_token(user, 'USER', salt)}@{_map_token(dom_low, 'DOM', salt)}"
    text = EMAIL_RE.sub(repl_email, text)

    # IPs
    text = IPV4_RE.sub(lambda m: _pseudonymize_ip(m.group(0), salt, map_private=map_private_ips), text)

    # Domains/FQDNs (avoid re-scrubbing already replaced or 10.x.x.x)
    def repl_fqdn(m):
        dom = m.group(1)
        if dom.startswith(("DOM-", "10.")):
            return dom
        return _map_token(dom.lower(), "DOM", salt)
    text = FQDN_RE.sub(repl_fqdn, text)

    # Hostname-like tokens
    def repl_machine(m):
        name = m.group(1)
        if name.startswith(("HOST-", "DOM-", "USER-")):
            return name
        return _map_token(name, "HOST", salt)
    text = MACHINE_RE.sub(repl_machine, text)

    return text

# ---------- HTML obfuscation ----------
def _obfuscate_html_str(
    html: str,
    *,
    salt: str,
    scrub_attrs: Iterable[str],
    map_private_ips: bool,
    keep_real_domain_in_emails: bool,
    mask_email_local_only: bool,
) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for node in soup.find_all(string=True):
        if node.parent and node.parent.name in ("script", "style"):
            continue
        new_text = _scrub_text(
            str(node),
            salt=salt,
            map_private_ips=map_private_ips,
            keep_real_domain_in_emails=keep_real_domain_in_emails,
            mask_email_local_only=mask_email_local_only,
        )
        if new_text != node:
            node.replace_with(new_text)

    for tag in soup.find_all(True):
        for attr in scrub_attrs:
            if tag.has_attr(attr):
                val = tag[attr]
                if isinstance(val, list):
                    tag[attr] = [
                        _scrub_text(
                            v,
                            salt=salt,
                            map_private_ips=map_private_ips,
                            keep_real_domain_in_emails=keep_real_domain_in_emails,
                            mask_email_local_only=mask_email_local_only,
                        )
                        for v in val
                    ]
                elif isinstance(val, str):
                    tag[attr] = _scrub_text(
                        val,
                        salt=salt,
                        map_private_ips=map_private_ips,
                        keep_real_domain_in_emails=keep_real_domain_in_emails,
                        mask_email_local_only=mask_email_local_only,
                    )
    return str(soup)

# ---------- JSON obfuscation ----------
def _split_csv_names(s: Optional[str]) -> Optional[Set[str]]:
    if not s:
        return None
    vals = [v.strip() for v in s.split(",") if v.strip()]
    return set(v.lower() for v in vals) if vals else None

def _obfuscate_json_obj(
    obj: Any,
    *,
    salt: str,
    map_private_ips: bool,
    keep_real_domain_in_emails: bool,
    mask_email_local_only: bool,
    json_fields: Optional[Set[str]] = None,        # If provided: scrub only these field names (case-insensitive)
    json_exclude_fields: Optional[Set[str]] = None,# If provided: never scrub these field names
    scrub_json_keys: bool = False,                 # If True, also scrub key **names**
    _current_key: Optional[str] = None,            # Internal: parent key (case preserved)
) -> Any:
    """
    Recursively scrub strings in JSON while preserving types.
    - If json_fields is provided, only scrub values where key name is in the set.
    - If json_exclude_fields is provided, never scrub values where key name is in the set.
    - If scrub_json_keys is True, key names themselves are scrubbed (can break downstream consumers).
    """
    if isinstance(obj, dict):
        new_d = {}
        for k, v in obj.items():
            # Decide new key
            new_k = _scrub_text(
                k,
                salt=salt,
                map_private_ips=map_private_ips,
                keep_real_domain_in_emails=keep_real_domain_in_emails,
                mask_email_local_only=mask_email_local_only,
            ) if (scrub_json_keys and isinstance(k, str)) else k

            # Determine if the value should be scrubbed based on key name
            k_l = k.lower() if isinstance(k, str) else None
            allow_by_fields = (json_fields is None) or (k_l in json_fields)
            blocked_by_exclude = (json_exclude_fields is not None) and (k_l in json_exclude_fields)

            if isinstance(v, (dict, list)):
                new_d[new_k] = _obfuscate_json_obj(
                    v,
                    salt=salt,
                    map_private_ips=map_private_ips,
                    keep_real_domain_in_emails=keep_real_domain_in_emails,
                    mask_email_local_only=mask_email_local_only,
                    json_fields=json_fields,
                    json_exclude_fields=json_exclude_fields,
                    scrub_json_keys=scrub_json_keys,
                    _current_key=k,
                )
            elif isinstance(v, str) and allow_by_fields and not blocked_by_exclude:
                new_d[new_k] = _scrub_text(
                    v,
                    salt=salt,
                    map_private_ips=map_private_ips,
                    keep_real_domain_in_emails=keep_real_domain_in_emails,
                    mask_email_local_only=mask_email_local_only,
                )
            else:
                new_d[new_k] = v
        return new_d

    if isinstance(obj, list):
        return [
            _obfuscate_json_obj(
                item,
                salt=salt,
                map_private_ips=map_private_ips,
                keep_real_domain_in_emails=keep_real_domain_in_emails,
                mask_email_local_only=mask_email_local_only,
                json_fields=json_fields,
                json_exclude_fields=json_exclude_fields,
                scrub_json_keys=scrub_json_keys,
                _current_key=_current_key,
            )
            for item in obj
        ]

    if isinstance(obj, str):
        # No key context here (list of strings or root string); scrub unless fields were explicitly specified
        if json_fields is not None and _current_key is None:
            return obj  # Without a key, cannot match json_fields; leave as-is
        return _scrub_text(
            obj,
            salt=salt,
            map_private_ips=map_private_ips,
            keep_real_domain_in_emails=keep_real_domain_in_emails,
            mask_email_local_only=mask_email_local_only,
        )

    # Numbers, booleans, null
    return obj

def _obfuscate_json_str(
    js: str,
    *,
    salt: str,
    map_private_ips: bool,
    keep_real_domain_in_emails: bool,
    mask_email_local_only: bool,
    json_fields: Optional[str] = None,
    json_exclude_fields: Optional[str] = None,
    scrub_json_keys: bool = False,
    json_indent: Optional[int] = None,
) -> str:
    data = json.loads(js)
    scrubbed = _obfuscate_json_obj(
        data,
        salt=salt,
        map_private_ips=map_private_ips,
        keep_real_domain_in_emails=keep_real_domain_in_emails,
        mask_email_local_only=mask_email_local_only,
        json_fields=_split_csv_names(json_fields),
        json_exclude_fields=_split_csv_names(json_exclude_fields),
        scrub_json_keys=scrub_json_keys,
    )
    return json.dumps(scrubbed, ensure_ascii=False, indent=json_indent)

# ---------- Helpers ----------
def _detect_format_from_suffix(path: Path) -> str:
    suf = path.suffix.lower()
    if suf in (".html", ".htm"):
        return "html"
    if suf == ".json":
        return "json"
    return "html"  # default for backward compatibility

# ---------- Fire CLI ----------
class Obfuscator:
    # ========== Unified file ==========
    def file(
        self,
        in_path: str,
        out_path: Optional[str] = None,
        *,
        format: str = "auto",   # auto|html|json
        salt: str = "soc-obfuscator-2025",
        attrs: str = "href,src",              # HTML only
        map_private_ips: bool = True,
        keep_real_domain_in_emails: bool = False,
        mask_email_local_only: bool = False,
        overwrite: bool = True,
        encoding: str = "utf-8",
        # JSON options
        json_fields: Optional[str] = None,         # e.g., "email,ip,hostname"
        json_exclude_fields: Optional[str] = None, # e.g., "comment,notes"
        scrub_json_keys: bool = False,
        json_indent: Optional[int] = None,         # e.g., 2
    ) -> str:
        """
        Obfuscate a single file (HTML or JSON).

        Args:
          in_path: Input file path.
          out_path: Output path (default based on input name and format).
          format: "auto" (by extension), "html", or "json".
          attrs: (HTML) Comma-separated attributes to scrub (e.g., "href,src,data-url").
          json_fields: (JSON) Only scrub these keys (case-insensitive). If omitted, scrub all string values.
          json_exclude_fields: (JSON) Never scrub these keys.
          scrub_json_keys: (JSON) Also scrub key names (may break downstream consumers).
          json_indent: (JSON) Indentation (e.g., 2). Default compact.
        """
        in_p = Path(in_path)
        if not in_p.exists():
            raise FileNotFoundError(f"Not found: {in_path}")

        fmt = _detect_format_from_suffix(in_p) if format == "auto" else format.lower()
        if fmt not in ("html", "json"):
            raise ValueError('format must be "auto", "html", or "json"')

        if out_path is None:
            stem = in_p.stem
            if fmt == "html":
                out_path = str(in_p.with_name(stem + "_redacted.html"))
            else:
                out_path = str(in_p.with_name(stem + "_redacted.json"))

        out_p = Path(out_path)
        if out_p.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {out_path}")

        with open(in_p, "r", encoding=encoding, errors="ignore") as f:
            content = f.read()

        if fmt == "html":
            scrubbed = _obfuscate_html_str(
                content,
                salt=salt,
                scrub_attrs=[a.strip() for a in attrs.split(",") if a.strip()],
                map_private_ips=map_private_ips,
                keep_real_domain_in_emails=keep_real_domain_in_emails,
                mask_email_local_only=mask_email_local_only,
            )
        else:
            scrubbed = _obfuscate_json_str(
                content,
                salt=salt,
                map_private_ips=map_private_ips,
                keep_real_domain_in_emails=keep_real_domain_in_emails,
                mask_email_local_only=mask_email_local_only,
                json_fields=json_fields,
                json_exclude_fields=json_exclude_fields,
                scrub_json_keys=scrub_json_keys,
                json_indent=json_indent,
            )

        with open(out_p, "w", encoding=encoding) as f:
            f.write(scrubbed)
        return str(out_p)

    # ========== HTML-only aliases (backwards compatible) ==========
    def file_html(self, *args, **kwargs) -> str:
        kwargs["format"] = "html"
        return self.file(*args, **kwargs)

    def stdin_html(
        self,
        *,
        salt: str = "soc-obfuscator-2025",
        attrs: str = "href,src",
        map_private_ips: bool = True,
        keep_real_domain_in_emails: bool = False,
        mask_email_local_only: bool = False,
        encoding: str = "utf-8",
    ) -> None:
        html = sys.stdin.read()
        scrubbed = _obfuscate_html_str(
            html,
            salt=salt,
            scrub_attrs=[a.strip() for a in attrs.split(",") if a.strip()],
            map_private_ips=map_private_ips,
            keep_real_domain_in_emails=keep_real_domain_in_emails,
            mask_email_local_only=mask_email_local_only,
        )
        sys.stdout.write(scrubbed)

    def dir_html(
        self,
        in_dir: str,
        out_dir: Optional[str] = None,
        *,
        salt: str = "soc-obfuscator-2025",
        attrs: str = "href,src",
        map_private_ips: bool = True,
        keep_real_domain_in_emails: bool = False,
        mask_email_local_only: bool = False,
        pattern: str = "*.html",
        recurse: bool = True,
        overwrite: bool = True,
        encoding: str = "utf-8",
    ) -> List[str]:
        in_root = Path(in_dir)
        if not in_root.is_dir():
            raise NotADirectoryError(f"Not a directory: {in_dir}")

        out_root = Path(out_dir) if out_dir else in_root.with_name(in_root.name + "_redacted")
        out_root.mkdir(parents=True, exist_ok=True)

        outputs = []
        files = list(in_root.rglob(pattern) if recurse else in_root.glob(pattern))
        for fp in files:
            rel = fp.relative_to(in_root)
            out_path = out_root / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            outputs.append(
                self.file_html(
                    str(fp),
                    str(out_path),
                    salt=salt,
                    attrs=attrs,
                    map_private_ips=map_private_ips,
                    keep_real_domain_in_emails=keep_real_domain_in_emails,
                    mask_email_local_only=mask_email_local_only,
                    overwrite=overwrite,
                    encoding=encoding,
                )
            )
        return outputs

    # ========== JSON-only ==========
    def file_json(self, *args, **kwargs) -> str:
        kwargs["format"] = "json"
        return self.file(*args, **kwargs)

    def stdin_json(
        self,
        *,
        salt: str = "soc-obfuscator-2025",
        map_private_ips: bool = True,
        keep_real_domain_in_emails: bool = False,
        mask_email_local_only: bool = False,
        json_fields: Optional[str] = None,
        json_exclude_fields: Optional[str] = None,
        scrub_json_keys: bool = False,
        json_indent: Optional[int] = None,
        encoding: str = "utf-8",
    ) -> None:
        js = sys.stdin.read()
        scrubbed = _obfuscate_json_str(
            js,
            salt=salt,
            map_private_ips=map_private_ips,
            keep_real_domain_in_emails=keep_real_domain_in_emails,
            mask_email_local_only=mask_email_local_only,
            json_fields=json_fields,
            json_exclude_fields=json_exclude_fields,
            scrub_json_keys=scrub_json_keys,
            json_indent=json_indent,
        )
        sys.stdout.write(scrubbed)

    def dir_json(
        self,
        in_dir: str,
        out_dir: Optional[str] = None,
        *,
        salt: str = "soc-obfuscator-2025",
        map_private_ips: bool = True,
        keep_real_domain_in_emails: bool = False,
        mask_email_local_only: bool = False,
        recurse: bool = True,
        overwrite: bool = True,
        encoding: str = "utf-8",
        json_fields: Optional[str] = None,
        json_exclude_fields: Optional[str] = None,
        scrub_json_keys: bool = False,
        json_indent: Optional[int] = None,
        pattern: str = "*.json",
    ) -> List[str]:
        in_root = Path(in_dir)
        if not in_root.is_dir():
            raise NotADirectoryError(f"Not a directory: {in_dir}")

        out_root = Path(out_dir) if out_dir else in_root.with_name(in_root.name + "_redacted")
        out_root.mkdir(parents=True, exist_ok=True)

        outputs = []
        files = list(in_root.rglob(pattern) if recurse else in_root.glob(pattern))
        for fp in files:
            rel = fp.relative_to(in_root)
            out_path = out_root / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            outputs.append(
                self.file_json(
                    str(fp),
                    str(out_path),
                    salt=salt,
                    map_private_ips=map_private_ips,
                    keep_real_domain_in_emails=keep_real_domain_in_emails,
                    mask_email_local_only=mask_email_local_only,
                    overwrite=overwrite,
                    encoding=encoding,
                    json_fields=json_fields,
                    json_exclude_fields=json_exclude_fields,
                    scrub_json_keys=scrub_json_keys,
                    json_indent=json_indent,
                )
            )
        return outputs

    # ========== Generic STDIN (auto/default html to preserve old behavior) ==========
    def stdin(
        self,
        *,
        format: str = "html",  # html|json
        salt: str = "soc-obfuscator-2025",
        attrs: str = "href,src",
        map_private_ips: bool = True,
        keep_real_domain_in_emails: bool = False,
        mask_email_local_only: bool = False,
        encoding: str = "utf-8",
        json_fields: Optional[str] = None,
        json_exclude_fields: Optional[str] = None,
        scrub_json_keys: bool = False,
        json_indent: Optional[int] = None,
    ) -> None:
        data = sys.stdin.read()
        if format.lower() == "json":
            out = _obfuscate_json_str(
                data,
                salt=salt,
                map_private_ips=map_private_ips,
                keep_real_domain_in_emails=keep_real_domain_in_emails,
                mask_email_local_only=mask_email_local_only,
                json_fields=json_fields,
                json_exclude_fields=json_exclude_fields,
                scrub_json_keys=scrub_json_keys,
                json_indent=json_indent,
            )
        else:
            out = _obfuscate_html_str(
                data,
                salt=salt,
                scrub_attrs=[a.strip() for a in attrs.split(",") if a.strip()],
                map_private_ips=map_private_ips,
                keep_real_domain_in_emails=keep_real_domain_in_emails,
                mask_email_local_only=mask_email_local_only,
            )
        sys.stdout.write(out)

    # ========== Generic dir (auto by suffix) ==========
    def dir(
        self,
        in_dir: str,
        out_dir: Optional[str] = None,
        *,
        format: str = "auto",  # auto|html|json
        salt: str = "soc-obfuscator-2025",
        attrs: str = "href,src",  # HTML
        map_private_ips: bool = True,
        keep_real_domain_in_emails: bool = False,
        mask_email_local_only: bool = False,
        recurse: bool = True,
        overwrite: bool = True,
        encoding: str = "utf-8",
        pattern: Optional[str] = None,       # default by format
        # JSON options
        json_fields: Optional[str] = None,
        json_exclude_fields: Optional[str] = None,
        scrub_json_keys: bool = False,
        json_indent: Optional[int] = None,
    ) -> List[str]:
        """
        Obfuscate all files in a directory, HTML or JSON.
        - format=auto: detects by file extension (.html/.htm => html, .json => json)
        - pattern default: *.html for html; *.json for json; *.* for auto (filters inside loop)
        """
        in_root = Path(in_dir)
        if not in_root.is_dir():
            raise NotADirectoryError(f"Not a directory: {in_dir}")

        out_root = Path(out_dir) if out_dir else in_root.with_name(in_root.name + "_redacted")
        out_root.mkdir(parents=True, exist_ok=True)

        fmt = format.lower()
        if fmt == "html":
            pat = pattern or "*.html"
            candidates = list(in_root.rglob(pat) if recurse else in_root.glob(pat))
        elif fmt == "json":
            pat = pattern or "*.json"
            candidates = list(in_root.rglob(pat) if recurse else in_root.glob(pat))
        else:
            pat = pattern or "*.*"
            candidates = list(in_root.rglob(pat) if recurse else in_root.glob(pat))
            # Filter to supported types
            candidates = [p for p in candidates if p.suffix.lower() in (".html", ".htm", ".json")]

        outputs: List[str] = []
        for fp in candidates:
            rel = fp.relative_to(in_root)
            out_path = out_root / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)

            detected = _detect_format_from_suffix(fp) if fmt == "auto" else fmt
            outputs.append(
                self.file(
                    str(fp),
                    str(out_path.with_suffix(".html" if detected == "html" else ".json")),
                    format=detected,
                    salt=salt,
                    attrs=attrs,
                    map_private_ips=map_private_ips,
                    keep_real_domain_in_emails=keep_real_domain_in_emails,
                    mask_email_local_only=mask_email_local_only,
                    overwrite=overwrite,
                    encoding=encoding,
                    json_fields=json_fields,
                    json_exclude_fields=json_exclude_fields,
                    scrub_json_keys=scrub_json_keys,
                    json_indent=json_indent,
                )
            )
        return outputs

if __name__ == "__main__":
    import fire
    fire.Fire(Obfuscator)

# ---------------- Usage ----------------
# HTML (unchanged behavior):
# python obfuscate_data_cli.py file alert.html
# python obfuscate_data_cli.py file alert.html out.html --format=html
# cat alert.html | python obfuscate_data_cli.py stdin --format=html > out.html
# python obfuscate_data_cli.py dir ./reports --format=html --recurse=True

# Keep images (only scrub links):
# python obfuscate_data_cli.py file alert.html --attrs=href

# JSON:
# python obfuscate_data_cli.py file data.json                         # auto-detect by extension
# python obfuscate_data_cli.py file data.json out.json --format=json
# cat data.json | python obfuscate_data_cli.py stdin --format=json > out.json
# python obfuscate_data_cli.py dir ./exports --format=json --recurse=True

# JSON field controls:
#   Only scrub selected fields:
# python obfuscate_data_cli.py file data.json --format=json --json_fields="email,ip,hostname"
#   Never scrub certain fields:
# python obfuscate_data_cli.py file data.json --format=json --json_exclude_fields="comment,notes"
#   Also scrub key names (use with caution):
# python obfuscate_data_cli.py file data.json --format=json --scrub_json_keys=True
#   Pretty-print result:
# python obfuscate_data_cli.py file data.json --format=json --json_indent=2