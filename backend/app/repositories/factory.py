"""
Repository Factory for CyberShield
Provides the active repository implementation based on DB_BACKEND environment variable.
"""
import os
import logging
from app.config import Config
from app.repositories.base import BaseRepository
from app.repositories.mysql_repo import MySQLRepository
from app.repositories.mongo_repo import MongoRepository

logger = logging.getLogger(__name__)

_repository_instance: BaseRepository = None

def get_repository() -> BaseRepository:
    global _repository_instance
    if _repository_instance is not None:
        return _repository_instance

    backend = Config.DB_BACKEND.lower()
    logger.info("Initializing CyberShield repository using backend: %s", backend)

    if backend == "mongo":
        _repository_instance = MongoRepository(
            uri=Config.MONGO_URI,
            database=Config.MONGO_DATABASE,
            fallback=Config.ENABLE_DEV_FALLBACK
        )
    elif backend == "sqlite":
        _repository_instance = MySQLRepository(
            use_sqlite=True,
            sqlite_path=Config.SQLITE_PATH,
            fallback=False
        )
    else:  # mysql
        _repository_instance = MySQLRepository(
            host=Config.MYSQL_HOST,
            port=Config.MYSQL_PORT,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DATABASE,
            fallback=Config.ENABLE_DEV_FALLBACK,
            sqlite_path=Config.SQLITE_PATH
        )

    return _repository_instance

def reset_repository_for_testing(backend: str = "sqlite") -> BaseRepository:
    """Utility to hot-swap repository backend for cross-database pytest suite."""
    global _repository_instance
    if backend == "mongo":
        _repository_instance = MongoRepository(fallback=True)
    elif backend == "sqlite":
        _repository_instance = MySQLRepository(use_sqlite=True, sqlite_path=":memory:", fallback=False)
    else:
        _repository_instance = MySQLRepository(fallback=True, sqlite_path=":memory:")
    return _repository_instance
