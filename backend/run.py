import os
from app import create_app
from app.config import Config

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", Config.PORT))
    print(f"[INFO] CyberShield API starting on port {port} [Backend: {Config.DB_BACKEND}]...")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes"),
    )
