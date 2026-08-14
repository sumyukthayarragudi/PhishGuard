import math
import re
from urllib.parse import urlparse


# =========================================================
# CONSTANTS — FROM PROJECT DOCUMENTATION
# =========================================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".tk",
    ".gq",
    ".ml",
    ".buzz",
    ".club",
    ".icu",
    ".info",
    ".work",
]

BRAND_KEYWORDS = [
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "bank",
    "chase",
    "wellsfargo",
    "citi",
    "amex",
]

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "rb.gy",
]

SUSPICIOUS_PATH_KEYWORDS = [
    "login",
    "secure",
    "verify",
    "update",
    "account",
    "confirm",
    "signin",
    "authenticate",
    "password",
    "credential",
]

HOMOGRAPH_PATTERNS = [
    r"paypa1",
    r"g[o0]{2}gle",
    r"amaz[o0]n",
    r"micr[o0]s[o0]ft",
    r"faceb[o0]{2}k",
    r"app1e",
    r"netf[l1]ix",
]

URGENCY_PHRASES = [
    "act now",
    "immediately",
    "urgent",
    "suspended",
    "locked",
    "expire",
    "within 24 hours",
    "action required",
    "last warning",
    "final notice",
    "account will be",
    "verify now",
]

CREDENTIAL_PHRASES = [
    "enter your password",
    "confirm your identity",
    "update your payment",
    "verify your account",
    "social security",
    "credit card number",
    "bank account",
    "login credentials",
    "ssn",
    "pin number",
]

EMOTIONAL_PHRASES = [
    "congratulations",
    "you've won",
    "selected winner",
    "claim your prize",
    "fear of missing",
    "limited time",
    "exclusive offer",
    "act fast",
]

TRUSTED_DOMAINS = [
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "gov.in",
    "edu",
]


# =========================================================
# SIGMOID
# =========================================================

def sigmoid(x):
    return 1 / (1 + math.exp(-x))


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    features = []

    lower = url.lower()

    try:
        parsed = urlparse(
            lower if lower.startswith("http") else "http://" + lower
        )

        hostname = parsed.hostname or ""

    except Exception:
        hostname = lower.split("/")[0]


    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    for tld in SUSPICIOUS_TLDS:

        if hostname.endswith(tld):

            features.append({
                "name": "Suspicious TLD",
                "score": 30,
                "impact": "high",
                "explanation":
                    f'Domain uses high-risk TLD "{tld}" commonly associated with phishing'
            })

            break


    # -----------------------------------------------------
    # Brand impersonation
    # -----------------------------------------------------

    for brand in BRAND_KEYWORDS:

        is_official = (
            hostname.endswith(f"{brand}.com")
            or hostname.endswith(f".{brand}.com")
            or hostname.endswith(f"{brand}.org")
            or hostname.endswith(f".{brand}.org")
            or hostname.endswith(f"{brand}.co")
            or hostname.endswith(f".{brand}.co")
        )

        if brand in hostname and not is_official:

            features.append({
                "name": "Brand Impersonation",
                "score": 30,
                "impact": "high",
                "explanation":
                    f'Domain appears to impersonate "{brand}"'
            })

            break


    # -----------------------------------------------------
    # IP address
    # -----------------------------------------------------

    if re.match(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        hostname
    ):

        features.append({
            "name": "IP Address Domain",
            "score": 25,
            "impact": "high",
            "explanation":
                "Uses IP address instead of domain name — common in phishing"
        })


    # -----------------------------------------------------
    # Homograph attack
    # -----------------------------------------------------

    for pattern in HOMOGRAPH_PATTERNS:

        match = re.search(pattern, hostname, re.IGNORECASE)

        if match:

            # Don't flag official-looking brand domains
            official_brand = any(
                f"{brand}." in hostname
                for brand in BRAND_KEYWORDS
            )

            if not official_brand:

                features.append({
                    "name": "Homograph Attack",
                    "score": 25,
                    "impact": "high",
                    "explanation":
                        f'Potential lookalike characters detected in "{match.group(0)}"'
                })

                break


    # -----------------------------------------------------
    # URL shortener
    # -----------------------------------------------------

    for shortener in URL_SHORTENERS:

        if hostname == shortener:

            features.append({
                "name": "URL Shortener",
                "score": 20,
                "impact": "high",
                "explanation":
                    f'Uses URL shortener "{shortener}" to mask true destination'
            })

            break


    # -----------------------------------------------------
    # Encoded characters
    # -----------------------------------------------------

    if (
        re.search(r"%[0-9a-f]{2}", url, re.IGNORECASE)
        or "base64" in url.lower()
    ):

        features.append({
            "name": "Encoded Characters",
            "score": 20,
            "impact": "high",
            "explanation":
                "Contains encoded or obfuscated characters in URL"
        })


    # -----------------------------------------------------
    # Simulated low domain popularity
    # -----------------------------------------------------

    if (
        len(hostname) > 20
        or re.search(r"[0-9]{4,}", hostname)
    ):

        features.append({
            "name": "Low Domain Popularity",
            "score": 20,
            "impact": "high",
            "explanation":
                "Domain appears to have very low traffic — typical of disposable phishing domains"
        })


    # -----------------------------------------------------
    # Simulated recent DNS changes
    # -----------------------------------------------------

    if (
        re.search(r"\d{6,}", hostname)
        or len(hostname.split(".")) > 3
    ):

        features.append({
            "name": "Recent DNS Changes",
            "score": 15,
            "impact": "high",
            "explanation":
                "Domain shows signs of recent registration or DNS changes"
        })


    # -----------------------------------------------------
    # SSL / HTTPS
    # -----------------------------------------------------

    if not lower.startswith("https"):

        features.append({
            "name": "No HTTPS",
            "score": 5,
            "impact": "low",
            "explanation":
                "Connection is not encrypted — missing HTTPS"
        })


    # -----------------------------------------------------
    # Excessive subdomains
    # -----------------------------------------------------

    subdomain_count = len(hostname.split(".")) - 2

    if subdomain_count > 3:

        features.append({
            "name": "Excessive Subdomains",
            "score": 15,
            "impact": "medium",
            "explanation":
                f"{subdomain_count} subdomains detected — used to confuse users"
        })


    # -----------------------------------------------------
    # Long URL
    # -----------------------------------------------------

    if len(url) > 75:

        features.append({
            "name": "Long URL",
            "score": 15,
            "impact": "medium",
            "explanation":
                f"URL length ({len(url)} chars) exceeds safe threshold"
        })


    return features


# =========================================================
# EMAIL ANALYSIS
# =========================================================

def analyze_email(email):

    features = []

    lower = email.lower()


    # -----------------------------------------------------
    # Credential request
    # -----------------------------------------------------

    for phrase in CREDENTIAL_PHRASES:

        if phrase in lower:

            features.append({
                "name": "Credential Request",
                "score": 30,
                "impact": "high",
                "explanation":
                    f'Contains "{phrase}" — a strong phishing indicator'
            })

            break


    # -----------------------------------------------------
    # Urgent language
    # -----------------------------------------------------

    for phrase in URGENCY_PHRASES:

        if phrase in lower:

            features.append({
                "name": "Urgent Language",
                "score": 25,
                "impact": "high",
                "explanation":
                    f'Contains urgency phrase "{phrase}" — common social engineering tactic'
            })

            break


    # -----------------------------------------------------
    # Suspicious links
    # -----------------------------------------------------

    url_pattern = r"(https?://[^\s]+|bit\.ly|tinyurl|cutt\.ly)"

    urls = re.findall(url_pattern, lower, re.IGNORECASE)

    if urls:

        has_suspicious_link = any(
            any(shortener in u for shortener in URL_SHORTENERS)
            or any(tld in u for tld in SUSPICIOUS_TLDS)
            for u in urls
        )

        if has_suspicious_link:

            features.append({
                "name": "Suspicious Link",
                "score": 25,
                "impact": "high",
                "explanation":
                    "Email contains suspicious or shortened URLs"
            })


    # -----------------------------------------------------
    # SPF / DKIM simulation
    # -----------------------------------------------------

    if (
        "noreply" in lower
        or "no-reply" in lower
        or "donotreply" in lower
    ):

        features.append({
            "name": "Authentication Warning",
            "score": 25,
            "impact": "high",
            "explanation":
                "Sender pattern suggests potential SPF/DKIM authentication issues (simulated)"
        })


    # -----------------------------------------------------
    # Lookalike sender domain
    # -----------------------------------------------------

    for pattern in HOMOGRAPH_PATTERNS:

        if re.search(pattern, lower, re.IGNORECASE):

            features.append({
                "name": "Lookalike Sender Domain",
                "score": 20,
                "impact": "high",
                "explanation":
                    "Sender appears to use a lookalike domain mimicking a known brand"
            })

            break


    # -----------------------------------------------------
    # Free email provider for business
    # -----------------------------------------------------

    free_providers = [
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com"
    ]

    if (
        any(provider in lower for provider in free_providers)
        and (
            "invoice" in lower
            or "payment" in lower
            or "account" in lower
        )
    ):

        features.append({
            "name": "Free Email for Business",
            "score": 15,
            "impact": "high",
            "explanation":
                "Uses free email provider for business-related communication"
        })


    # -----------------------------------------------------
    # Emotional manipulation
    # -----------------------------------------------------

    for phrase in EMOTIONAL_PHRASES:

        if phrase in lower:

            features.append({
                "name": "Emotional Manipulation",
                "score": 20,
                "impact": "high",
                "explanation":
                    f'Contains emotional trigger "{phrase}"'
            })

            break


    # -----------------------------------------------------
    # Financial urgency
    # -----------------------------------------------------

    if (
        "wire transfer" in lower
        or "bitcoin" in lower
        or "gift card" in lower
        or "payment overdue" in lower
    ):

        features.append({
            "name": "Financial Urgency",
            "score": 15,
            "impact": "high",
            "explanation":
                "Contains financial urgency language often used in phishing"
        })


    # -----------------------------------------------------
    # Dangerous attachment
    # -----------------------------------------------------

    if (
        ".exe" in lower
        or ".zip" in lower
        or "macro" in lower
        or ".docm" in lower
        or "enable content" in lower
    ):

        features.append({
            "name": "Dangerous Attachment",
            "score": 20,
            "impact": "high",
            "explanation":
                "Mentions executable or macro-enabled attachments"
        })


    # -----------------------------------------------------
    # Multiple links
    # -----------------------------------------------------

    if len(urls) > 3:

        features.append({
            "name": "Multiple Links",
            "score": 10,
            "impact": "medium",
            "explanation":
                f"Contains {len(urls)} links — excessive for typical communication"
        })


    # -----------------------------------------------------
    # Sender mismatch
    # -----------------------------------------------------

    if "from:" in lower and "reply-to:" in lower:

        features.append({
            "name": "Sender Mismatch",
            "score": 15,
            "impact": "medium",
            "explanation":
                "From and Reply-To addresses appear different (simulated)"
        })


    # -----------------------------------------------------
    # Attachment reference
    # -----------------------------------------------------

    if (
        "attachment" in lower
        or "attached" in lower
        or "download" in lower
    ):

        features.append({
            "name": "Attachment Reference",
            "score": 15,
            "impact": "medium",
            "explanation":
                "References attachments or downloads"
        })


    # -----------------------------------------------------
    # Grammar anomaly
    # -----------------------------------------------------

    grammar_matches = re.findall(
        r"\b(kindly|dear sir|dear customer|dear user|valued customer)\b",
        lower
    )

    if grammar_matches:

        features.append({
            "name": "Grammar Anomaly",
            "score": 10,
            "impact": "low",
            "explanation":
                "Contains generic/formulaic language typical of phishing emails"
        })


    # -----------------------------------------------------
    # Generic greeting
    # -----------------------------------------------------

    if re.search(
        r"dear (sir|madam|customer|user|valued|account holder)",
        lower
    ):

        features.append({
            "name": "Generic Greeting",
            "score": 5,
            "impact": "low",
            "explanation":
                "Uses generic greeting instead of personal name"
        })


    # -----------------------------------------------------
    # Repetitive CTA
    # -----------------------------------------------------

    cta_matches = re.findall(
        r"(click here|click now|click below|verify now|update now)",
        lower
    )

    if len(cta_matches) > 1:

        features.append({
            "name": "Repetitive CTA",
            "score": 10,
            "impact": "medium",
            "explanation":
                f"{len(cta_matches)} repetitive call-to-action phrases detected"
        })


    return features


# =========================================================
# MAIN DETECTION
# =========================================================

def detect_phishing(input_text, input_type):

    if input_type == "url":
        features = analyze_url(input_text)
    else:
        features = analyze_email(input_text)


    # =====================================================
    # STEP 2 — RULE RISK SCORE
    # =====================================================

    risk_score = min(
        100,
        max(
            0,
            sum(feature["score"] for feature in features)
        )
    )


    # =====================================================
    # STEP 3 — WEIGHTED PROBABILITY
    # =====================================================

    weighted_sum = 0

    for feature in features:

        if feature["impact"] == "high":
            weight = 1.5

        elif feature["impact"] == "medium":
            weight = 1.0

        else:
            weight = 0.5

        weighted_sum += feature["score"] * weight


    raw_probability = (
        sigmoid((weighted_sum - 45) / 15)
        * 100
    )


    # =====================================================
    # STEP 4 — CALIBRATION
    # =====================================================

    calibrated_probability = raw_probability


    high_risk_count = sum(
        1
        for feature in features
        if feature["impact"] == "high"
        and feature["score"] >= 20
    )

    medium_risk_count = sum(
        1
        for feature in features
        if feature["impact"] == "medium"
    )


    # High-risk calibration
    if high_risk_count >= 3:

        calibrated_probability += 20

    elif high_risk_count == 2:

        calibrated_probability += 10

    elif high_risk_count == 1:

        calibrated_probability += 3


    # Medium-risk calibration
    if medium_risk_count >= 3:

        calibrated_probability += 5


    # =====================================================
    # HARD RULES
    # =====================================================

    has_brand_impersonation = any(
        feature["name"] in [
            "Brand Impersonation",
            "Homograph Attack"
        ]
        for feature in features
    )

    has_shortener_with_keywords = (
        any(
            feature["name"] == "URL Shortener"
            for feature in features
        )
        and
        any(
            feature["name"] == "Suspicious Path Keywords"
            for feature in features
        )
    )

    has_credential_request = any(
        feature["name"] == "Credential Request"
        for feature in features
    )


    if (
        has_brand_impersonation
        or has_credential_request
    ):

        calibrated_probability = max(
            calibrated_probability,
            75
        )


    if has_shortener_with_keywords:

        calibrated_probability = max(
            calibrated_probability,
            65
        )


    # =====================================================
    # LOW-SIGNAL ADJUSTMENT
    # =====================================================

    if (
        len(features) <= 1
        and risk_score < 25
    ):

        calibrated_probability *= 0.5


    # =====================================================
    # TRUSTED DOMAIN CALIBRATION
    # =====================================================

    if input_type == "url":

        try:

            parsed = urlparse(
                input_text
                if input_text.lower().startswith("http")
                else "http://" + input_text
            )

            hostname = parsed.hostname or ""

        except Exception:

            hostname = ""

        is_trusted = any(
            domain in hostname
            for domain in TRUSTED_DOMAINS
        )

        if is_trusted:

            calibrated_probability -= 25


    # Final calibration
    calibrated_probability = min(
        100,
        round(calibrated_probability)
    )


    # No detected features
    if len(features) == 0:

        calibrated_probability = 5


    # =====================================================
    # STEP 5 — CLASSIFICATION
    # =====================================================

    if (
        calibrated_probability >= 75
        and high_risk_count >= 2
    ):

        risk_level = "high"

        risk_label = "High Risk — Likely Phishing"


    elif calibrated_probability >= 45:

        risk_level = "suspicious"

        risk_label = "Suspicious — Needs Verification"


    else:

        risk_level = "low"

        risk_label = "Likely Safe"


    # Conservative rule
    if (
        risk_level == "low"
        and risk_score > 35
    ):

        risk_level = "suspicious"

        risk_label = "Suspicious — Needs Verification"

        calibrated_probability = max(
            calibrated_probability,
            30
        )


    # =====================================================
    # XAI SUMMARY
    # =====================================================

    top_features = sorted(
        [
            feature
            for feature in features
            if feature["score"] > 0
        ],
        key=lambda feature: feature["score"],
        reverse=True
    )[:3]


    if top_features:

        summary = ". ".join(
            feature["explanation"]
            for feature in top_features
        ) + "."

    else:

        summary = (
            "No significant risk indicators "
            "found in the input."
        )


    # =====================================================
    # FINAL RESULT
    # =====================================================

    return {

        "inputType": input_type,

        "input": input_text,

        "riskScore": risk_score,

        "rawProbability": round(raw_probability),

        "calibratedProbability": calibrated_probability,

        "riskLevel": risk_level,

        "riskLabel": risk_label,

        "features": sorted(
            features,
            key=lambda feature: feature["score"],
            reverse=True
        ),

        "summary": summary
    }