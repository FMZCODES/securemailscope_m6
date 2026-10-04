import logging
import os
from urllib.parse import urlparse

import certifi
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.server_api import ServerApi

load_dotenv()

logger = logging.getLogger(__name__)


def _clean_env_value(value: str | None) -> str | None:
    """Normalize values copied into Render environment variables."""
    if value is None:
        return None

    value = value.strip()

    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
        value = value[1:-1].strip()

    return value or None


MONGODB_URI = _clean_env_value(os.getenv("MONGODB_URI"))
MONGODB_DATABASE = _clean_env_value(os.getenv("MONGODB_DATABASE")) or "securemailscope"

# Accept an accidental full .env line pasted into the Render VALUE field.
if MONGODB_URI and MONGODB_URI.startswith("MONGODB_URI="):
    MONGODB_URI = MONGODB_URI.split("=", 1)[1].strip()

client = None
db = None
analyses_collection = None

# Keeps the complete result available to the dashboard if MongoDB is
# temporarily unavailable. MongoDB remains the real persistent store.
_memory_analyses: dict[str, dict] = {}


def _validate_uri(uri: str) -> bool:
    try:
        parsed = urlparse(uri)
    except Exception:
        return False

    return parsed.scheme in {"mongodb", "mongodb+srv"} and bool(parsed.netloc)


def connect_mongodb() -> bool:
    """Connect to MongoDB Atlas and force a real ping."""

    global client, db, analyses_collection

    if not MONGODB_URI:
        logger.error("MONGODB_URI is missing from the environment")
        return False

    if not _validate_uri(MONGODB_URI):
        logger.error(
            "Invalid MONGODB_URI. It must begin with mongodb:// or mongodb+srv://"
        )
        return False

    try:
        client = MongoClient(
            MONGODB_URI,
            tls=True,
            tlsCAFile=certifi.where(),
            server_api=ServerApi("1"),
            serverSelectionTimeoutMS=15000,
            connectTimeoutMS=10000,
            socketTimeoutMS=15000,
            retryWrites=True,
        )

        client.admin.command("ping")

        db = client[MONGODB_DATABASE]
        analyses_collection = db["analyses"]

        logger.info(
            "MongoDB connected successfully: database=%s",
            MONGODB_DATABASE,
        )
        return True

    except Exception as exc:
        logger.error("MongoDB connection failed: %s", exc)
        client = None
        db = None
        analyses_collection = None
        return False


def check_connection() -> bool:
    return connect_mongodb()


def get_analyses_collection():
    global analyses_collection

    if analyses_collection is None:
        connect_mongodb()

    return analyses_collection


def save_analysis(analysis: dict) -> bool:
    """
    Cache the complete result immediately, then persist it to MongoDB.
    Returns True only when MongoDB persistence succeeds.
    """

    analysis_id = analysis.get("analysis_id")
    if analysis_id:
        _memory_analyses[analysis_id] = analysis

    collection = get_analyses_collection()

    if collection is None:
        logger.warning(
            "MongoDB unavailable. Analysis %s is available only in memory.",
            analysis_id,
        )
        return False

    try:
        collection.replace_one(
            {"analysis_id": analysis_id},
            analysis,
            upsert=True,
        )
        logger.info("Analysis %s saved to MongoDB", analysis_id)
        return True

    except Exception as exc:
        logger.error("MongoDB save failed: %s", exc)
        return False


def get_analysis(analysis_id: str):
    """Retrieve from MongoDB first, then use the current-process cache."""

    collection = get_analyses_collection()

    if collection is not None:
        try:
            result = collection.find_one(
                {"analysis_id": analysis_id},
                {"_id": 0},
            )
            if result is not None:
                _memory_analyses[analysis_id] = result
                return result
        except Exception as exc:
            logger.error("MongoDB read failed: %s", exc)

    return _memory_analyses.get(analysis_id)


def delete_analysis(analysis_id: str) -> bool:
    _memory_analyses.pop(analysis_id, None)

    collection = get_analyses_collection()
    if collection is None:
        return False

    try:
        result = collection.delete_one({"analysis_id": analysis_id})
        return result.deleted_count > 0
    except Exception as exc:
        logger.error("MongoDB delete failed: %s", exc)
        return False
