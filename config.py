import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
    DATABASE = os.path.join(BASE_DIR, "instance", "sentinellog.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MODEL_FOLDER = os.path.join(BASE_DIR, "models")
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024          # 10 MB upload limit
    ALLOWED_EXTENSIONS = {"csv", "txt", "log"}

    # Detection thresholds (used for reference labels and alert typing)
    BRUTE_FORCE_FAILURES = 8        # failed logins per IP per hour
    SPRAY_USER_THRESHOLD = 4        # distinct usernames per IP per hour
