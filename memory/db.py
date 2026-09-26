"""Only place that opens the Atlas connection."""
from pymongo import MongoClient
from config.config import MONGODB_URI, DB_NAME, COLLECTION

_client = None

def get_client():
    global _client
    if _client is None:
        if not MONGODB_URI:
            raise RuntimeError("MONGODB_URI empty. Fill .env from .env.example.")
        _client = MongoClient(MONGODB_URI)
    return _client

def get_collection():
    return get_client()[DB_NAME][COLLECTION]
