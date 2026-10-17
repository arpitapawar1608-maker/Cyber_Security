# SentinelLog – Cybersecurity Log Analytics & Anomaly Detection Dashboard

A defensive application (Python + Flask + HTML/JS) that analyses authentication and server logs and detects unusual
patterns such as repeated failed logins or abnormal access.

## Run in VS Code
```bash
python -m venv venv
venv\Scripts\activate          # Windows   (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 and sign in with the admin account `admin` / `Admin@123` (the application has a single admin login).
Then: **Upload** `sample_logs/sample_auth.csv` → **Analytics** → **Prediction → Run anomaly detection** → **Dashboard / History / Reports**.

## Modules
Secure Admin Login · Log Upload · Log Parsing · Event Analytics · Anomaly Detection · Incident Dashboard · Report Export

## Pages
Login → Dashboard → Master Data Management → Data Entry / Upload → Analytics → Prediction → History → Reports

## Database (4 tables)
| Table | Fields / keys |
|---|---|
| users | user_id PK, username, password_hash, role |
| log_sources | source_id PK, source_name, server_name, source_type |
| security_logs | log_id PK, source_id FK, event_time, ip_address, username, event_type, status |
| alerts | alert_id PK, log_id FK, alert_type, severity, score, created_at, status |

## Code layers
`routes.py` (presentation) · `services/` parser, analytics, detection (business logic) · `repository.py`, `db.py` (database access)

## Analytics & ML
Descriptive and diagnostic analytics on the Analytics page (the Diagnostic section also shows the classification, regression and clustering scores); predictive analytics (forecast of failed logins for the next 6 hours) on the Analytics page, and anomaly prediction on the Prediction page. Event types are one-hot
encoded per IP-hour window, features are scaled, data is split 70/30, and two candidates (statistical Z-score threshold and
Isolation Forest) are compared on accuracy, precision, recall, F1 and confusion matrix. The best model is saved to
`models/best_model.joblib`; its score (0–100) becomes the alert severity and each alert is stored with a timestamp.
