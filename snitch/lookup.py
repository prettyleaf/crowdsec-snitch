"""Network lookups: whether an IP is hosted, and who handles its abuse reports."""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request

import dns.exception
import dns.resolver

USER_AGENT = "crowdsec-snitch"
ABUSIX_ZONE = "abuse-contacts.abusix.zone"
MAX_CONTACTS = 3
TIMEOUT = 15

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


class TransientLookupError(Exception):
    """The lookup could not complete now and is worth retrying later."""


def clean_contacts(values: list[str]) -> list[str]:
    """Keep well-formed addresses only: these strings come from outside sources."""
    seen: list[str] = []
    for value in values:
        address = value.strip().lower()
        if EMAIL.fullmatch(address) and address not in seen:
            seen.append(address)
    return seen[:MAX_CONTACTS]


def _get_json(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.load(response)


def hosting_info(ip: str) -> dict:
    """Classify an IP through ip-api.com. Its free tier offers plain HTTP only."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,mobile,proxy,hosting"
    try:
        data = _get_json(url)
    except (OSError, ValueError) as exc:
        raise TransientLookupError(f"ip-api: {exc}") from exc
    if data.get("status") != "success":
        raise TransientLookupError(f"ip-api: {data.get('message', 'lookup failed')}")
    return data


def abusix_contacts(ip: str) -> list[str]:
    pointer = ipaddress.ip_address(ip).reverse_pointer
    name = pointer.rsplit(".", 2)[0] + "." + ABUSIX_ZONE
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise TransientLookupError(f"abusix: {exc}") from exc
    values: list[str] = []
    for record in answer:
        text = b"".join(record.strings).decode("ascii", "replace")
        values.extend(text.split(","))
    return clean_contacts(values)


def _rdap_abuse_emails(entities: list) -> list[str]:
    found: list[str] = []
    for entity in entities or []:
        if "abuse" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray") or [None, []]
            for field in vcard[1]:
                if field and field[0] == "email":
                    found.append(str(field[3]))
        found.extend(_rdap_abuse_emails(entity.get("entities")))
    return found


def rdap_contacts(ip: str) -> list[str]:
    try:
        data = _get_json(f"https://rdap.org/ip/{ip}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise TransientLookupError(f"rdap: HTTP {exc.code}") from exc
    except (OSError, ValueError) as exc:
        raise TransientLookupError(f"rdap: {exc}") from exc
    return clean_contacts(_rdap_abuse_emails(data.get("entities")))


def find_contacts(ip: str) -> tuple[list[str], str]:
    """Return (addresses, source). A failure in one source falls through to the other."""
    error: TransientLookupError | None = None
    for source, finder in (("abusix", abusix_contacts), ("rdap", rdap_contacts)):
        try:
            contacts = finder(ip)
        except TransientLookupError as exc:
            error = exc
            continue
        if contacts:
            return contacts, source
    if error:
        raise error
    return [], ""
