"""Configuration settings for the security scanner."""
import os

# Model configuration
OPENAI_MODEL = os.getenv("CRI_FUZZING_MODEL", "gpt-4.1")
OPENAI_TIMEOUT = float(os.getenv("CRI_OPENAI_TIMEOUT", "240"))

# Check if OpenAI API key is available
USE_OPENAI = bool(os.getenv("OPENAI_API_KEY"))