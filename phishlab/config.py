"""
Configuration loader. Reads IMAP credentials and paths from .env.
Never hardcodes secrets - .env stays local and is gitignored.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _required(name: str) -> str:
    """Fetch an env var or raise a clear error if missing."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            f"Check that {PROJECT_ROOT / '.env'} exists and has all IMAP_* fields."
        )
    return value


# IMAP credentials - required
IMAP_HOST = _required("IMAP_HOST")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
IMAP_USER = _required("IMAP_USER")
IMAP_PASSWORD = _required("IMAP_PASSWORD")
IMAP_FOLDER = os.getenv("IMAP_FOLDER", "INBOX")

# Paths - derived from project structure
MODEL_PATH = PROJECT_ROOT / "model" / "artifacts" / "model_v2.pkl"
DB_PATH = PROJECT_ROOT / "phishlab.db"