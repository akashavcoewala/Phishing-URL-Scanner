# Phishing URL Scanner

##  Project Overview

The **Phishing URL Scanner** is a cybersecurity tool designed to detect and classify potentially malicious URLs. The project utilizes machine learning and external APIs to analyze URLs for phishing threats, helping users stay safe online.

## 📌 Features

-  **URL Analysis**: Scans URLs for malicious patterns.
-  **Machine Learning Integration**: Uses predictive models for phishing detection.
-  **API Support**: Integrates external threat intelligence APIs.
-  **Logging & Reporting**: Stores scan results for review.
-  **Command-Line & GUI Support**: Available as a script and a user-friendly interface.

🔹 Detects phishing URLs, integrates with Google Safe Browsing API, supports bulk scanning, generates reports.")

## 🏗️ Tech Stack

- **Programming Language**: Python
- **Libraries**: `requests`, `pandas`, `scikit-learn`, `Flask` (optional for GUI)
- **Databases**: CSV for logging results (can be extended to MongoDB or PostgreSQL)

## 🛠️ Installation & Setup

### 1️. Clone the Repository

```bash
git clone https://github.com/akashavcoewala/Phishing-URL-Scanner.git
cd Phishing-URL-Scanner
```

### 2️. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️. Setup API Keys (If Required)

Create a `.env` file and store sensitive keys securely:

```env
API_KEY=your_api_key_here
```

**Important:** Do not commit `.env` files. Add it to `.gitignore`.

### 4️. Run the Scanner

```bash
python phishing_scanner.py
```

## 📸 Screenshots
-added to folder



## 📄 Documentation

A detailed project document is available: **[Project\_Documentation.md](Project_Documentation.md)**

## 🤖 Future Enhancements

- Deploy as a Web App using Flask/Django.
- Integrate AI-powered URL classification.
- Store results in a cloud database.

## 🏆 Contributors

- **Akash Raut** ([@akashavcoewala](https://github.com/akashavcoewala))

## 📜 License

MIT License. Free to use .

---

**Stay safe from phishing threats! 🚀🔐**



