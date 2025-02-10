import xmltodict
import os

def parse_dmarc_report(xml_file):
    """
    Parses a DMARC XML report and extracts key details.

    Args:
        xml_file (str): Path to the DMARC XML file.

    Returns:
        list: A list of parsed DMARC report data.
    """
    if not os.path.exists(xml_file):
        raise FileNotFoundError(f"Error: File {xml_file} not found.")

    with open(xml_file, "r", encoding="utf-8") as file:
        try:
            data = xmltodict.parse(file.read())
        except Exception as e:
            raise ValueError(f"Error parsing XML file: {e}")

    # Ensure 'feedback' key exists
    if "feedback" not in data:
        raise KeyError("Invalid DMARC XML: 'feedback' section missing.")

    # Extract metadata
    report_metadata = data["feedback"].get("report_metadata", {})
    policy_published = data["feedback"].get("policy_published", {})
    record_entries = data["feedback"].get("record", [])

    if isinstance(record_entries, dict):
        record_entries = [record_entries]

    reports = []
    for record in record_entries:
        reports.append({
            "org_name": report_metadata.get("org_name", "Unknown"),
            "email": report_metadata.get("email", "Unknown"),
            "report_id": report_metadata.get("report_id", "Unknown"),
            "begin_date": report_metadata.get("date_range", {}).get("begin", "Unknown"),
            "end_date": report_metadata.get("date_range", {}).get("end", "Unknown"),
            "domain": policy_published.get("domain", "Unknown"),
            "policy": policy_published.get("p", "Unknown"),
            "spf_result": record["row"]["policy_evaluated"].get("spf", "Unknown"),
            "dkim_result": record["row"]["policy_evaluated"].get("dkim", "Unknown"),
            "source_ip": record["row"].get("source_ip", "Unknown"),
            "count": record["row"].get("count", 0)
        })

    return reports
