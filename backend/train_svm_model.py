import joblib
import pandas as pd
from sklearn.svm import SVC

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


# Train SVM
print("\nTraining SVM...")

model = SVC(
    probability=True,
    random_state=42
)

model.fit(X, y)


# Save model
joblib.dump(model, "svm_model.pkl")

print("SVM model saved as svm_model.pkl")


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