import os
import logging

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "securemailscope")

client = None
db = None
analyses_collection = None


def connect_mongodb() -> bool:
    """
    Connect to MongoDB Atlas.

    Returns:
        True  -> MongoDB connection successful
        False -> MongoDB unavailable
    """

    global client
    global db
    global analyses_collection

    if not MONGODB_URI:
        logger.error("MONGODB_URI is missing from .env")
        return False

    try:
        client = MongoClient(
            MONGODB_URI,

            # Connection settings
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=10000,

            # Atlas requires TLS
            tls=True,
        )

        # Force a real connection test.
        client.admin.command("ping")

        db = client[MONGODB_DATABASE]

        analyses_collection = db["analyses"]

        logger.info("MongoDB connected successfully")

        return True

    except Exception as exc:
        logger.error("MongoDB connection failed: %s", exc)

        client = None
        db = None
        analyses_collection = None

        return False


def check_connection() -> bool:
    """
    Check whether MongoDB is available.
    """

    return connect_mongodb()


def get_analyses_collection():
    """
    Return the analyses collection.

    Returns:
        MongoDB collection if connected.
        None if MongoDB is unavailable.
    """

    global analyses_collection

    if analyses_collection is None:
        connect_mongodb()

    return analyses_collection


def save_analysis(analysis: dict):
    """
    Save an analysis to MongoDB.

    MongoDB failure does NOT crash the PCAP analysis.
    """

    collection = get_analyses_collection()

    if collection is None:
        logger.warning(
            "MongoDB unavailable. Analysis will not be persisted."
        )
        return False

    try:
        collection.insert_one(analysis)

        logger.info(
            "Analysis %s saved to MongoDB",
            analysis.get("analysis_id"),
        )

        return True

    except Exception as exc:
        logger.error(
            "MongoDB save failed: %s",
            exc,
        )

        return False


def get_analysis(analysis_id: str):
    """
    Retrieve an analysis by ID.
    """

    collection = get_analyses_collection()

    if collection is None:
        return None

    try:
        return collection.find_one(
            {"analysis_id": analysis_id},
            {"_id": 0},
        )

    except Exception as exc:
        logger.error(
            "MongoDB read failed: %s",
            exc,
        )

        return None


def delete_analysis(analysis_id: str):
    """
    Delete an analysis by ID.
    """

    collection = get_analyses_collection()

    if collection is None:
        return False

    try:
        result = collection.delete_one(
            {"analysis_id": analysis_id}
        )

        return result.deleted_count > 0

    except Exception as exc:
        logger.error(
            "MongoDB delete failed: %s",
            exc,
        )

        return False