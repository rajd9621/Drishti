"""Drishti configuration. All secrets come from environment variables only."""
from __future__ import annotations

import os


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip() in ("1", "true", "True", "yes")


# --- SLM ---
MODEL_ID = os.environ.get("DRISHTI_MODEL_ID", "Qwen/Qwen2.5-1.5B-Instruct")
ENABLE_SLM = _flag("DRISHTI_ENABLE_SLM", "0")  # if off, deterministic fallbacks run
SLM_MAX_NEW_TOKENS = int(os.environ.get("DRISHTI_MAX_NEW_TOKENS", "512"))

# --- optional official overlays (never hardcode keys) ---
WAQI_TOKEN = os.environ.get("WAQI_TOKEN")
IMD_API_KEY = os.environ.get("IMD_API_KEY")
IMD_JWT = os.environ.get("IMD_JWT")

# --- behaviour ---
CACHE_TTL_SECONDS = int(os.environ.get("DRISHTI_CACHE_TTL", "1800"))
HTTP_TIMEOUT = int(os.environ.get("DRISHTI_HTTP_TIMEOUT", "12"))
USER_AGENT = os.environ.get(
    "DRISHTI_USER_AGENT", "Drishti/1.0 (GeoAI Hackathon; contact: rajdubey1762@gmail.com)"
)
DEFAULT_RADIUS_KM = float(os.environ.get("DRISHTI_DEFAULT_RADIUS_KM", "5"))
MAX_CANDIDATES = int(os.environ.get("DRISHTI_MAX_CANDIDATES", "10"))
MAX_FORECAST_DAYS = int(os.environ.get("DRISHTI_FORECAST_DAYS", "7"))

# --- thresholds for the recommendation ---
GOOD_SCORE = 60      # >= this is a "go"
AVOID_SCORE = 35     # <= this is "avoid"
