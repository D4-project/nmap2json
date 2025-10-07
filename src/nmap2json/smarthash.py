"""
This module will try to clean headers in reports
The goal is to generate a stable hash between two identical scan.

It blank some value of headers ( for example php session id cookie)
Before hashing the data with sha256

It process only some nse scripts results;
["http-headers", "http-security-headers"]

It does not process some sections in the hash.
["starttime", "endtime", "sha256"])

TODO:
This code should be heavily re-factored in ordre to have flexible configuration
in a yaml or json configuration file and massive speedup.
All regex should be pre-compiled at start for performances.
All Headers sould be processed once.
"""

import json
import hashlib
import re

# Headers where cleanup may occuers.
HEADERS_TOCLEAN = [
    "ETag",
    "CF-Ray",
    "Via",
    "X-Amz-Cf-Id",
    "content-security-policy-report-only",
    "www-authenticate",
    "request-id",
    "x-request-id",
    "x-runtime",
    "x-gitlab-meta",
]


def filter_keys(obj: dict | list, exclude_keys: list):
    """
    Recursively filter out specified keys from dictionaries and lists
    Used before hashing.
    """
    if isinstance(obj, dict):
        return {
            k: filter_keys(v, exclude_keys)
            for k, v in obj.items()
            if k not in exclude_keys
        }
    elif isinstance(obj, list):
        return [filter_keys(i, exclude_keys) for i in obj]
    else:
        return obj


def headers_smart_hash(obj: dict, exclude_keys=None):
    """
    Generate sha256 of normalised result result.
    """
    exclude_keys = exclude_keys or []
    filtered = filter_keys(obj, exclude_keys)  # Remove some fiels from report
    filtered = master_clean(
        filtered, ["http-headers", "http-security-headers"]
    )  # Heaving filtering out.
    obj_str = json.dumps(
        filtered,
    )  # dump result before hashing.
    return hashlib.sha256(obj_str.encode("utf-8")).hexdigest()


###############################################
# Masking


def mask_same_length(match):
    """
    This replace by X with the good size.
    """
    return "".join("X" if c != " " else " " for c in match.group(0))


def mask_value(match):
    """
    This replace the snd match group with X
    """
    value = match.group(2)
    masked = "X" * len(value)
    return f"{match.group(1)}{masked}"


def mask_cookie_value(match):
    """
    This replace the cookies values.
    """
    key = match.group(1)
    # value = match.group(2)  ; Lenght of the substitutions.
    suffix = match.group(3) or ""
    masked = "[REDACTED]"  # or X = value
    return f"{key}={masked}{suffix}"


###############################################
# Generic deletions


def no_time(nt_input: str):
    """
    Remove "time" from a string
    """
    # Regex pour les dates dans les headers
    pattern = (
        r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2}[- ]"
        + "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        + r"[- ]\d{4} \d{2}:\d{2}:\d{2} [A-Z]{2,4}"
    )
    return re.sub(pattern, mask_same_length, nt_input)


def no_uid(nu_input: str):
    """
    Remove Any UID references, for example
    04a843ac-a0e7-4b62-8abb-6495dbb70833
    """
    pattern = r"(?:[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12})"
    return re.sub(pattern, mask_same_length, nu_input)


###############################################$
# Custom deletions.


def anonymise_nonce(an_input: str):
    """
    replace nonce in some headers.
    """
    pattern = re.compile(r'nonce[-=]"?([a-zA-Z0-9_\-\+]+)')
    return pattern.sub(mask_same_length, an_input)


def anonymise_correlation_id(an_corr: str):
    """
    replace corelation id only in some headers.
    X-Gitlab-Meta: {"correlation_id":"01K6GEFC3J1D6KJT17DG7QGDA3","version":"1"}
    """
    pattern = re.compile(r'(correlation_id"[:]"([a-zA-Z0-9_\-\+]+))')
    return pattern.sub(mask_same_length, an_corr)


def anonymise_cookies(ac_input):
    """This function anonymise cookies value.
    # We do not replace exact size, since session cookies size varies.
    # And this could kill de unique hashing.
    """

    # Replace betwwen = and ; or endline
    pattern = re.compile(r"(Set-Cookie:\s*[^=]+)=([^;]+)(;[^\n]*|$)", re.IGNORECASE)
    return pattern.sub(mask_cookie_value, ac_input)


def anonymise_headers(input_text: str, headers: list):
    """
    This function will anonymise headers
    and also some pamareters in headers.
    Need to be refactored ... too many scans.
    """
    for header in headers:
        # Cherche le header même si la ligne est indentée
        if re.search(
            rf"^\s*{re.escape(header)}\s*:", input_text, re.IGNORECASE | re.MULTILINE
        ):
            if header.lower().startswith(
                "content-security-policy"
            ) or header.lower().startswith("www-authenticate"):
                # Anonymise les nonce dans tout le texte (CSP complet)
                input_text = anonymise_nonce(input_text)
                return input_text
            elif header.lower().startswith("x-gitlab-meta"):
                input_text = anonymise_correlation_id(input_text)
                return input_text
        # Masque la valeur des autres headers
        pattern = re.compile(
            rf"(^\s*{re.escape(header)}\s*:\s*)(.+)", re.IGNORECASE | re.MULTILINE
        )
        input_text = pattern.sub(mask_value, input_text)
    return input_text


#######################################
# Main function.


def master_clean(not_dedup_nmap_result: dict, scripts: list):
    """
    This function will try to remove non relevant data inside a
    for example, etags, timestamp, cookies value...
    in order to be able to generate a smart hash that is not moving between two scans.

    """
    result = not_dedup_nmap_result.copy()  # duplicate the object.

    for port in result.get("ports"):
        if port.get("scripts"):
            for item in port.get("scripts"):
                for script in scripts:
                    if item.get("id") == script:
                        to_clean = item.get("output")
                        # Need to be put in a config file one day.
                        cleaned = anonymise_headers(
                            anonymise_cookies(no_uid(no_time(to_clean))),
                            HEADERS_TOCLEAN,
                        )
                        item["output"] = cleaned  # replace the headers
    return result
