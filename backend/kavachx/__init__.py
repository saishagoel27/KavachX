"""KavachX backend package."""

# Load backend/.env before any submodule reads os.environ at import time.
from dotenv import load_dotenv

from kavachx.core.config import ENV_FILE, export_to_environ

load_dotenv(ENV_FILE, override=False)
export_to_environ()

__all__ = ["ENV_FILE"]
