import joblib
import pandas as pd

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from utils.feature_extractor import extract_features
from risk_engine import detect_phishing


app = FastAPI(title="PhishGuard API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# LOAD MODELS
# =========================

rf_model = joblib.load("model.pkl")
svm_model = joblib.load("svm_model.pkl")

email_model = joblib.load("email_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# =========================
# REQUEST MODELS
# =========================

class URLRequest(BaseModel):
    url: str


class EmailRequest(BaseModel):
    email: str


# =========================
# HOME
# =========================

@app.get("/")
def home():
    return {
        "message": "PhishGuard API is running!"
    }


# =========================
# URL PREDICTION
# =========================

@app.post("/predict")
def predict_url(request: URLRequest):

    # =====================================================
    # EXTRACT FEATURES
    # =====================================================

    features = extract_features(request.url)

    features_df = pd.DataFrame([features])

    # =====================================================
    # RANDOM FOREST
    # =====================================================

    rf_prediction = rf_model.predict(features_df)[0]

    rf_probabilities = rf_model.predict_proba(features_df)[0]

    rf_confidence = max(rf_probabilities) * 100

    # =====================================================
    # SVM
    # =====================================================

    svm_prediction = svm_model.predict(features_df)[0]

    svm_probabilities = svm_model.predict_proba(features_df)[0]

    svm_confidence = max(svm_probabilities) * 100

    # =====================================================
    # MODEL AGREEMENT
    # =====================================================

    if rf_prediction == svm_prediction:

        agreement = "High"
        final_prediction = rf_prediction

    else:

        agreement = "Low"

        # Random Forest is the primary model
        final_prediction = rf_prediction

    # =====================================================
    # XAI / RISK ENGINE
    # =====================================================

    risk_result = detect_phishing(
        request.url,
        "url"
    )
    if final_prediction == "Phishing" and agreement == "High":
        display_risk_level = "high"
        display_risk_label = "High Risk - Likely Phishing"

    else:
        display_risk_level = risk_result["riskLevel"]
        display_risk_label = risk_result["riskLabel"]

    # =====================================================
    # HUMAN-READABLE REASONS
    # =====================================================

    reasons = []

    if not features["https"]:
        reasons.append(
            "URL is not using HTTPS."
        )

    if features["ip_address"]:
        reasons.append(
            "URL contains an IP address instead of a domain name."
        )

    if features["suspicious_keywords"] > 0:
        reasons.append(
            f"Detected {features['suspicious_keywords']} suspicious keyword(s)."
        )

    if features["hyphens"] >= 2:
        reasons.append(
            "URL contains multiple hyphens."
        )

    if features["length"] > 75:
        reasons.append(
            "URL is unusually long."
        )

    if features["dots"] > 3:
        reasons.append(
            "URL contains many subdomains."
        )

    if features["suspicious_tld"]:
        reasons.append(
            "URL uses a suspicious top-level domain."
        )

    if features["url_shortener"]:
        reasons.append(
            "URL uses a URL shortening service."
        )

    if features["brand_impersonation"]:
        reasons.append(
            "URL may be impersonating a known brand."
        )

    if features["homograph_attack"]:
        reasons.append(
            "URL contains non-standard characters that may indicate a homograph attack."
        )

    if features["sensitive_path_keywords"] > 0:
        reasons.append(
            "Sensitive keywords were detected in the URL path."
        )

    if features["at_symbol"]:
        reasons.append(
            "URL contains an @ symbol."
        )

    if features["double_slash_redirect"]:
        reasons.append(
            "URL contains a possible double-slash redirect pattern."
        )

    if not reasons:
        reasons.append(
            "No suspicious characteristics were detected."
        )

    # =====================================================
    # FINAL RESPONSE
    # =====================================================

    return {

        "url": request.url,

        # -------------------------
        # ML RESULT
        # -------------------------

        "prediction": final_prediction,

        "confidence": round(
            rf_confidence,
            2
        ),

        "agreement": agreement,

        "models": {

            "random_forest": {

                "prediction": rf_prediction,

                "confidence": round(
                    rf_confidence,
                    2
                )
            },

            "svm": {

                "prediction": svm_prediction,

                "confidence": round(
                    svm_confidence,
                    2
                )
            }
        },

        # -------------------------
        # EXISTING EXPLANATIONS
        # -------------------------

        "reasons": reasons,

        # -------------------------
        # 17 FEATURES
        # -------------------------

        "features": features,

        # -------------------------
        # XAI / RISK ENGINE
        # -------------------------

        "risk": {

            "riskScore": risk_result["riskScore"],

            "rawProbability": risk_result[
                "rawProbability"
            ],

            "calibratedProbability": risk_result[
                "calibratedProbability"
            ],

            "riskLevel": display_risk_level,

            "riskLabel": display_risk_label,


            "detectedFeatures": risk_result[
                "features"
            ],

            "summary": risk_result[
                "summary"
            ]
        }
    }

# =========================
# EMAIL PREDICTION
# =========================

@app.post("/predict-email")
def predict_email(request: EmailRequest):

    email_text = request.email

    # Convert email to TF-IDF representation
    email_vector = vectorizer.transform([email_text])

    # ML prediction
    prediction = email_model.predict(email_vector)[0]

    probabilities = email_model.predict_proba(email_vector)[0]

    confidence = max(probabilities) * 100

    # =========================
    # RULE-BASED EMAIL SIGNALS
    # =========================

    text = email_text.lower()

    suspicious_signals = []
    risk_score = 0

    # Urgency
    urgency_keywords = [
        "urgent",
        "act now",
        "immediately",
        "limited time",
        "don't miss",
        "last chance"
    ]

    if any(word in text for word in urgency_keywords):
        suspicious_signals.append(
            "Uses urgency or pressure tactics."
        )
        risk_score += 15

    # Money / payment
    payment_keywords = [
        "pay",
        "payment",
        "registration fee",
        "fee",
        "₹",
        "rs.",
        "rupees",
        "upi",
        "razorpay",
        "payment link"
    ]

    if any(word in text for word in payment_keywords):
        suspicious_signals.append(
            "Requests or promotes a payment."
        )
        risk_score += 20

    # Registration / offer
    promotional_keywords = [
        "register now",
        "registration",
        "offer",
        "limited",
        "certificate",
        "webinar",
        "live online",
        "join now"
    ]

    promotional_count = sum(
        word in text for word in promotional_keywords
    )

    if promotional_count >= 2:
        suspicious_signals.append(
            "Contains multiple promotional or registration signals."
        )
        risk_score += 15

    # External links
    if "http://" in text or "https://" in text:
        suspicious_signals.append(
            "Contains an external link."
        )
        risk_score += 15

    # Phone numbers
    import re

    phone_numbers = re.findall(
        r"\b\d{10}\b",
        text
    )

    if phone_numbers:
        suspicious_signals.append(
            "Contains phone numbers for direct contact."
        )
        risk_score += 10

    # Strong call to action
    cta_keywords = [
        "register now",
        "click here",
        "apply now",
        "sign up",
        "buy now",
        "get started"
    ]

    if any(word in text for word in cta_keywords):
        suspicious_signals.append(
            "Contains a strong call-to-action."
        )
        risk_score += 15

    # =========================
    # COMBINE ML + RULE SCORE
    # =========================

    ml_is_phishing = (
        str(prediction).lower() == "phishing"
    )

    if ml_is_phishing:
        risk_score += 30

    risk_score = min(risk_score, 100)

    # =========================
    # FINAL CLASSIFICATION
    # =========================

    if risk_score >= 60:
        final_prediction = "Phishing"

    elif risk_score >= 35:
        final_prediction = "Suspicious"

    else:
        final_prediction = prediction

    # =========================
    # DEFAULT REASON
    # =========================

    if not suspicious_signals:
        suspicious_signals.append(
            "No major suspicious email characteristics were detected."
        )

    return {

        "email": request.email,

        "prediction": final_prediction,

        "confidence": round(
            confidence,
            2
        ),

        "riskScore": risk_score,

        "mlPrediction": prediction,

        "mlConfidence": round(
            confidence,
            2
        ),

        "reasons": suspicious_signals
    }