import os
from fastapi import FastAPI
from parsers.dmarc_parser import parse_dmarc_report

app = FastAPI()

# Correct path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DMARC_FILE_PATH = os.path.join(BASE_DIR, "data/sample_dmarc_report.xml")

@app.get("/dmarc/reports/")
async def get_dmarc_report():
    """API endpoint to fetch parsed DMARC reports."""
    try:
        parsed_reports = parse_dmarc_report(DMARC_FILE_PATH)
        return {"reports": parsed_reports}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
