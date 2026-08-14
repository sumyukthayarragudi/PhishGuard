import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from utils.feature_extractor import extract_features


# Load dataset
data = pd.read_csv("data/dataset.csv")

print("Dataset loaded successfully.")
print("Total samples:", len(data))


# Extract features
features = []

for url in data["url"]:
    features.append(extract_features(url))

features_df = pd.DataFrame(features)

X = features_df
y = data["label"]

print("\nFeatures extracted successfully.")
print("Number of features:", len(features_df.columns))

print("\nFeatures used:")
for feature in features_df.columns:
    print("-", feature)


# Train Random Forest
print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)

# Training accuracy
predictions = model.predict(X)
accuracy = accuracy_score(y, predictions)

print(f"Random Forest Accuracy: {accuracy * 100:.2f}%")

# Save model
joblib.dump(model, "model.pkl")

print("Random Forest model saved as model.pkl")


# Test prediction
new_url = "http://secure-login.xyz"

new_features = extract_features(new_url)
new_features_df = pd.DataFrame([new_features])

prediction = model.predict(new_features_df)
probabilities = model.predict_proba(new_features_df)

confidence = max(probabilities[0]) * 100

print("\nTest URL:", new_url)
print("Prediction:", prediction[0])
print(f"Confidence: {confidence:.2f}%")
