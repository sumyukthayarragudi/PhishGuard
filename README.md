# 🛡️ PhishGuard

PhishGuard is a machine-learning-based phishing detection system designed to identify potentially malicious URLs and phishing emails.

It combines machine learning models with a risk-analysis engine to provide predictions, confidence scores, and understandable reasons behind the detection result.

## 🚀 Features

- 🔗 Phishing URL detection
- 📧 Phishing email detection
- 🤖 Random Forest and SVM models for URL classification
- 🧠 TF-IDF-based email classification
- 📊 Prediction confidence scores
- 🔍 Suspicious URL feature analysis
- ⚠️ Risk scoring and risk levels
- 💡 Human-readable explanations
- 🌐 Web-based frontend
- ⚡ FastAPI backend

## 🛠️ Tech Stack

### Frontend
- React
- TypeScript
- Vite
- Tailwind CSS

### Backend
- Python
- FastAPI
- Scikit-learn
- Pandas
- Joblib

### Machine Learning
- Random Forest
- Support Vector Machine (SVM)
- TF-IDF Vectorization
- Email classification model

## 📁 Project Structure

```text
PhishGuard/
│
├── backend/
│   ├── model.pkl
│   ├── svm_model.pkl
│   ├── email_model.pkl
│   ├── vectorizer.pkl
│   ├── risk_engine.py
│   ├── utils/
│   └── ...
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── ...
│
├── .gitignore
└── README.md