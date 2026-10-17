"""SentinelLog - Cybersecurity Log Analytics & Anomaly Detection Dashboard."""
import os

from flask import Flask

from config import Config
from db import close_db, init_db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    for folder in (app.config["UPLOAD_FOLDER"], app.config["MODEL_FOLDER"]):
        os.makedirs(folder, exist_ok=True)
    init_db(app)
    app.teardown_appcontext(close_db)

    from routes import register_routes
    register_routes(app)
    return app


if __name__ == "__main__":
    create_app().run(debug=True, port=5000)
