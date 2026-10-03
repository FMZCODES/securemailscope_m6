import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "securemailscope")

if not MONGODB_URI:
    raise ValueError("MONGODB_URI is missing from the .env file")

client = MongoClient(
    MONGODB_URI,
    serverSelectionTimeoutMS=5000
)

db = client[MONGODB_DATABASE]
analyses_collection = db["analyses"]


def check_connection():
    client.admin.command("ping")
    return True
