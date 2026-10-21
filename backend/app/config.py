import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    _is_production = os.getenv("FLASK_ENV", "development").lower() == "production"
    _development_secret = "development-only-change-me"
    SECRET_KEY = os.getenv("SECRET_KEY") or (_development_secret if not _is_production else None)
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or (_development_secret if not _is_production else None)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    # Database Backend selection: 'mysql' | 'mongo' | 'sqlite'
    DB_BACKEND = os.getenv("DB_BACKEND", "sqlite").lower()
    # Development fallback: if True and mysql/mongo is offline, fall back to SQLite/memory with an explicit warning
    ENABLE_DEV_FALLBACK = os.getenv("ENABLE_DEV_FALLBACK", "false").lower() in ("true", "1", "yes")

    # MySQL Configuration
    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "cybershield")

    # MongoDB Configuration
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/cybershield")
    MONGO_DATABASE = os.getenv("MONGO_DATABASE", "cybershield")

    # Standalone SQLite Configuration
    SQLITE_PATH = os.getenv("SQLITE_PATH", "cybershield_local.db")

    PORT = int(os.getenv("PORT", 5000))

    if _is_production and (not SECRET_KEY or not JWT_SECRET_KEY):
        raise RuntimeError("SECRET_KEY and JWT_SECRET_KEY must be set when FLASK_ENV=production")
