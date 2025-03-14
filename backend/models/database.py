"""
SQLite Database Setup for DMarking
Stores parsed DMARC reports for tracking and analysis
"""

import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime


# Ensure the directory exists
os.makedirs("backend/db", exist_ok=True)

# Define SQLite Database Path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data/dmarc_reports.db")
DATABASE_URL = "sqlite:///backend/db/dmarking.db"

# Setup SQLite Engine
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Create a Base Class for ORM
Base = declarative_base()

# Create a Session Factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Define the DMARC Reports Table
class DMARCReport(Base):
    __tablename__ = "dmarc_reports"

    id = Column(Integer, primary_key=True, index=True)
    org_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    report_id = Column(String, unique=True, nullable=False)
    begin_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    domain = Column(String, nullable=False)
    policy = Column(String, nullable=False)
    spf_result = Column(String, nullable=False)
    dkim_result = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    count = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create Tables if They Don’t Exist
def init_db():
    Base.metadata.create_all(bind=engine)

# Initialize Database
if __name__ == "__main__":
    init_db()
    print("✅ SQLite Database and Tables Created!")
