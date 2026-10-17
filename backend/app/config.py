import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "cybershield-production-jwt-key-default-2026")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cybershield-jwt-token-signing-secret-key-32bytes")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    DB_BACKEND = os.getenv("DB_BACKEND", "mysql").lower() # 'mysql' or 'mongo'
    ENABLE_DEV_FALLBACK = os.getenv("ENABLE_DEV_FALLBACK", "true").lower() in ("true", "1", "yes")

    # MySQL Configuration
    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "rootpassword")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "cybershield")

    # MongoDB Configuration
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/cybershield")
    MONGO_DATABASE = os.getenv("MONGO_DATABASE", "cybershield")

    PORT = int(os.getenv("PORT", 5000))
