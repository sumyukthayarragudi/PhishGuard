# 🛡️ PhishGuard

PhishGuard is a machine-learning-based phishing detection system designed to identify potentially malicious URLs and phishing emails.

It combines machine learning models with a risk-analysis engine to provide predictions, confidence scores, and understandable reasons behind the detection result using explainable AI (XAI).

## 🚀 Features

- 🔗 Phishing URL detection
- 📧 Phishing email detection
- 🤖 Random Forest and SVM models for URL classification
- 🧠 TF-IDF-based email classification
- 📊 Prediction confidence scores
- 🔍 Suspicious URL feature analysis
- ⚠️ Risk scoring and risk levels
- 💡 Human-readable explanations using XAI
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
- Pydantic
- Uvicorn

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
│   ├── data/
│   │   ├── dataset.csv
│   │   └── email_dataset.csv
│   │
│   ├── utils/
│   │   └── feature_extractor.py
│   │
│   ├── main.py
│   ├── risk_engine.py
│   ├── train_model.py
│   ├── train_svm_model.py
│   ├── train_email_model.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── ...
│
├── .gitignore
└── README.md
```

## ⚙️ How to Run

### 1. Run the Backend

Open a terminal and navigate to the backend:

```powershell
cd backend
```

Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install the required dependencies:

```powershell
python -m pip install -r requirements.txt
```

Start the FastAPI server:

```powershell
uvicorn main:app --reload
```

The backend will run at:

http://127.0.0.1:8000

### 2. Run the Frontend

Open a second terminal:

cd frontend

Install the frontend dependencies:

npm install

Start the development server:

npm run dev

The frontend will normally run at:

http://localhost:5173

##🔌 API Endpoints

URL Detection

POST /predict

Detects potentially malicious URLs and returns the prediction, confidence, model agreement, risk score, detected features, and human-readable reasons.

Email Detection

POST /predict-email

Analyses email text and returns the phishing prediction and confidence score.

## 🚀 Future Improvements

- 🔐 Real-time URL and email monitoring
- 📈 Improve model accuracy using larger and more diverse datasets
- 🧠 Integrate advanced XAI techniques such as SHAP or LIME
- 🌐 Deploy the application as a cloud-based service
- 🔄 Add continuous model retraining with new phishing data
- 🛡️ Add browser extension support for real-time phishing detection
- 📧 Support email analysis from email platforms
- 📊 Add detailed analytics and detection history
- 🔔 Add alerts for high-risk phishing attempts


👩‍💻Author: Yarragudi Sumyuktha
