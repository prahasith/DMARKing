import os
from fastapi import FastAPI, Depends
from datetime import datetime

app = FastAPI()

# Path to DMARC XML report
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DMARC_FILE_PATH = os.path.join(BASE_DIR, "data/sample_dmarc_report.xml")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/dmarc/reports/")
async def get_dmarc_reports(db: Session = Depends(get_db)):
    """Fetch all stored DMARC reports from the database."""
    reports = db.query(DMARCReport).all()
    return {"reports": reports}

@app.post("/dmarc/reports/")
async def parse_and_store_dmarc_report(db: Session = Depends(get_db)):
    """Parse DMARC XML, store results in the database, and return the inserted data."""
    try:
        parsed_reports = parse_dmarc_report(DMARC_FILE_PATH)
        
        for report in parsed_reports:
            new_report = DMARCReport(
                org_name=report["org_name"],
                email=report["email"],
                report_id=report["report_id"],
                begin_date=datetime.utcfromtimestamp(int(report["begin_date"])),
                end_date=datetime.utcfromtimestamp(int(report["end_date"])),
                domain=report["domain"],
                policy=report["policy"],
                spf_result=report["spf_result"],
                dkim_result=report["dkim_result"],
                source_ip=report["source_ip"],
                count=int(report["count"])
            )
            db.add(new_report)

        db.commit()
        return {"message": "DMARC reports parsed and stored successfully!"}

    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

