import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def load_env(key: str) -> str:
    """
    Load environment variables from a `.env` file.
    """
    val = os.getenv(key)
    if val is None:
        raise ValueError(f"Environment variable {key} is not set.")
        sys.exit()
    return val


load_dotenv(override=True)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR = BASE_DIR / "reports"
CONSOLE_LOGGING = load_env("CONSOLE_LOGGING").upper() == "TRUE"

APICALLS = DATA_DIR / "APIcalls.txt"
ADSLIBS = DATA_DIR / "ads.csv"


AAPT = load_env("AAPT_PATH")
AAPT = (BASE_DIR / AAPT).resolve()
if not Path(AAPT).exists():
    raise FileNotFoundError(f"AAPT not found at {AAPT}")

BAKSMALI = load_env("BAKSMALI_PATH")
BAKSMALI = (BASE_DIR / BAKSMALI).resolve()
if not Path(BAKSMALI).exists():
    raise FileNotFoundError(f"Baksmali not found at {BAKSMALI}")
