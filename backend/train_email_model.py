import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier


# Load dataset
data = pd.read_csv("data/email_dataset.csv")

print("Email dataset loaded successfully.")
print("Total samples:", len(data))


# Input and labels
X = data["email"]
y = data["label"]


# TF-IDF
vectorizer = TfidfVectorizer()

X_vectorized = vectorizer.fit_transform(X)

print("TF-IDF features created.")
print("Number of features:", X_vectorized.shape[1])


# Train Random Forest
print("\nTraining Email Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_vectorized, y)


# Save model and vectorizer
joblib.dump(model, "email_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("Email model saved as email_model.pkl")
print("Vectorizer saved as vectorizer.pkl")


# Test
test_email = "Urgent! Verify your bank account immediately."

test_vector = vectorizer.transform([test_email])

prediction = model.predict(test_vector)
probabilities = model.predict_proba(test_vector)

confidence = max(probabilities[0]) * 100

print("\nTest Email:", test_email)
print("Prediction:", prediction[0])
print(f"Confidence: {confidence:.2f}%")