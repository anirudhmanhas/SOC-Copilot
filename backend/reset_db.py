"""
SOC Copilot - Database Reset Script
Cleans and re-initializes all tables in the SQLite database for a fresh demo run.
"""

import sys
import os
from pathlib import Path

# Add backend directory to sys.path so app imports work cleanly
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.db import engine, Base
from app import models  # Ensures all models are registered on Base.metadata

def reset_database():
    print("[*] Resetting SOC Copilot database...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("[✓] All tables dropped and schema re-initialized successfully.")

if __name__ == "__main__":
    reset_database()

