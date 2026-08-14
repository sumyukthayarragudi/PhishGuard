import re
import math
from collections import Counter
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "password",
    "account",
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
]

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
]

BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "amazon",
    "apple",
    "facebook",
    "instagram",
    "netflix",
    "bank",
]


def url_length(url):
    return len(url)


def has_https(url):
    return url.lower().startswith("https://")


def count_dots(url):
    return url.count(".")


def count_hyphens(url):
    return url.count("-")


def has_ip_address(url):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return bool(re.search(pattern, url))


def suspicious_keywords(url):
    url_lower = url.lower()

    return sum(
        1 for word in SUSPICIOUS_KEYWORDS
        if word in url_lower
    )


def count_special_characters(url):
    return sum(
        1 for char in url
        if not char.isalnum()
        and char not in "/.:_-"
    )


def count_digits(url):
    return sum(char.isdigit() for char in url)


def suspicious_tld(url):
    url_lower = url.lower()

    return any(
        url_lower.endswith(tld)
        or f"{tld}/" in url_lower
        or f"{tld}?" in url_lower
        for tld in SUSPICIOUS_TLDS
    )


def is_url_shortener(url):
    try:
        domain = urlparse(url).netloc.lower()

        return domain in URL_SHORTENERS

    except Exception:
        return False


def count_subdomains(url):
    try:
        domain = urlparse(url).netloc.split(":")[0]

        parts = domain.split(".")

        if len(parts) <= 2:
            return 0

        return len(parts) - 2

    except Exception:
        return 0


def brand_impersonation(url):
    url_lower = url.lower()

    try:
        domain = urlparse(url).netloc.lower()

        return any(
            brand in domain
            for brand in BRANDS
        ) and not any(
            domain.endswith(f"{brand}.com")
            for brand in BRANDS
        )

    except Exception:
        return False


def homograph_attack(url):
    try:
        domain = urlparse(url).netloc

        return any(
            ord(char) > 127
            for char in domain
        )

    except Exception:
        return False


def sensitive_path_keywords(url):
    try:
        path = urlparse(url).path.lower()

        keywords = [
            "login",
            "signin",
            "verify",
            "payment",
            "checkout",
            "account",
            "password",
            "confirm",
        ]

        return sum(
            1 for word in keywords
            if word in path
        )

    except Exception:
        return 0


def has_at_symbol(url):
    return "@" in url


def has_double_slash_redirect(url):
    try:
        parsed = urlparse(url)

        return "//" in parsed.path

    except Exception:
        return False


def calculate_entropy(url):
    if not url:
        return 0.0

    counts = Counter(url)
    length = len(url)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def extract_features(url):

    return {
        "length": url_length(url),
        "https": has_https(url),
        "dots": count_dots(url),
        "hyphens": count_hyphens(url),
        "ip_address": has_ip_address(url),
        "suspicious_keywords": suspicious_keywords(url),
        "special_characters": count_special_characters(url),
        "digits": count_digits(url),
        "suspicious_tld": suspicious_tld(url),
        "url_shortener": is_url_shortener(url),
        "subdomains": count_subdomains(url),
        "brand_impersonation": brand_impersonation(url),
        "homograph_attack": homograph_attack(url),
        "sensitive_path_keywords": sensitive_path_keywords(url),
        "at_symbol": has_at_symbol(url),
        "double_slash_redirect": has_double_slash_redirect(url),
        "entropy": calculate_entropy(url),
    }