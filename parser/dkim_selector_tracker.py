import sqlite3
import dns.resolver
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import json
import time


class DkimSelectorTracker:
    """
    Track DKIM selectors and their associated DNS records from DMARC reports.
    Also fetches and stores the actual DKIM TXT records from DNS.
    """
    
    def __init__(self, db_path: str = 'dkim_selectors.db'):
        """
        Initialize the DKIM selector tracker.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
    
    def _create_tables(self):
        """Create the necessary database tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # DKIM Selectors table - stores DKIM selectors and their DNS records
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS dkim_selectors (
            selector_id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,                    -- Domain the selector is for
            selector TEXT NOT NULL,                  -- DKIM selector name
            dkim_key TEXT,                           -- The DNS TXT record content
            first_seen_date TEXT NOT NULL,           -- When this selector was first observed
            last_seen_date TEXT NOT NULL,            -- When this selector was last observed
            last_dns_check TEXT,                     -- When DNS was last checked
            age_days INTEGER DEFAULT 0,              -- Age of the key in days
            key_creation_date TEXT,                  -- When the key was first created/detected
            is_active BOOLEAN DEFAULT 1,             -- Whether the selector is still active
            dns_exists BOOLEAN,                      -- Whether DNS record exists
            total_pass_count INTEGER DEFAULT 0,      -- Total pass results
            total_fail_count INTEGER DEFAULT 0,      -- Total fail results
            last_result TEXT,                        -- Last authentication result
            UNIQUE(domain, selector)
        )
        ''')
        
        # Create index on domain for faster lookups
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_dkim_selectors_domain ON dkim_selectors(domain)
        ''')
        
        # Check if age tracking columns exist, add if needed
        cursor.execute("PRAGMA table_info(dkim_selectors)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'key_creation_date' not in columns:
            cursor.execute('ALTER TABLE dkim_selectors ADD COLUMN key_creation_date TEXT')
        
        self.conn.commit()
        cursor.close()
    
    def lookup_dkim_record(self, domain: str, selector: str) -> Tuple[bool, Optional[str]]:
        """
        Look up the DKIM DNS record for a domain and selector.
        
        Args:
            domain: The domain name
            selector: The DKIM selector
            
        Returns:
            Tuple of (record_exists, record_text)
        """
        try:
            # Construct the DKIM DNS name (selector._domainkey.domain)
            dkim_name = f"{selector}._domainkey.{domain}"
            
            # Query DNS for TXT record
            answers = dns.resolver.resolve(dkim_name, 'TXT')
            
            # Combine all TXT records
            txt_data = []
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_data.append(txt_string.decode('utf-8'))
            
            # Return the full TXT record
            return True, "".join(txt_data)
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            # Record doesn't exist or other DNS error
            return False, None
        except Exception as e:
            print(f"Error looking up DKIM record for {selector}._domainkey.{domain}: {str(e)}")
            return False, None
    
    def track_dkim_selector(self, domain: str, selector: str, result: str, report_id: str = None):
        """
        Track a DKIM selector observed in a DMARC report and check its DNS record.
        
        Args:
            domain: The domain name
            selector: The DKIM selector
            result: The authentication result ('pass', 'fail', etc.)
            report_id: Optional DMARC report ID
        """
        if not domain or not selector:
            return
            
        cursor = self.conn.cursor()
        current_date = datetime.now().isoformat()
        
        try:
            # Check if this selector is already in the database
            cursor.execute('''
            SELECT selector_id, first_seen_date, dkim_key, last_dns_check, 
                   total_pass_count, total_fail_count, is_active, 
                   key_creation_date, age_days
            FROM dkim_selectors
            WHERE domain = ? AND selector = ?
            ''', (domain, selector))
            
            existing = cursor.fetchone()
            
            # Look up DNS record
            dns_check_needed = True
            if existing:
                # If we checked recently (within 24 hours), don't check again
                if existing['last_dns_check']:
                    last_check = datetime.fromisoformat(existing['last_dns_check'])
                    time_since_check = (datetime.now() - last_check).total_seconds() / 3600
                    if time_since_check < 24:  # Less than 24 hours ago
                        dns_check_needed = False
            
            dns_exists = False
            dkim_key = None
            key_creation_date = None
            age_days = 0
            
            if dns_check_needed:
                dns_exists, dkim_key = self.lookup_dkim_record(domain, selector)
            
            if existing:
                # Update existing record
                
                # Update pass/fail counts
                pass_count = existing['total_pass_count']
                fail_count = existing['total_fail_count']
                
                if result.lower() == 'pass':
                    pass_count += 1
                else:
                    fail_count += 1
                
                # Handle key creation date and age
                if existing['key_creation_date']:
                    key_creation_date = existing['key_creation_date']
                    # Calculate age based on key creation date
                    creation_dt = datetime.fromisoformat(key_creation_date)
                    age_days = (datetime.now() - creation_dt).days
                else:
                    # If no creation date stored but we have a key, use first seen date
                    key_creation_date = existing['first_seen_date']
                    creation_dt = datetime.fromisoformat(key_creation_date)
                    age_days = (datetime.now() - creation_dt).days
                
                # If the DNS record changed, reset creation date and age
                if dns_check_needed and dns_exists and dkim_key and existing['dkim_key'] != dkim_key:
                    key_creation_date = current_date
                    age_days = 0
                
                # Keep existing values if we didn't check DNS
                if not dns_check_needed:
                    dkim_key = existing['dkim_key']
                    dns_exists = existing['dns_exists'] if 'dns_exists' in existing else None
                    
                # Update the record
                cursor.execute('''
                UPDATE dkim_selectors SET
                    last_seen_date = ?,
                    dkim_key = ?,
                    last_dns_check = ?,
                    key_creation_date = ?,
                    age_days = ?,
                    dns_exists = ?,
                    is_active = ?,
                    total_pass_count = ?,
                    total_fail_count = ?,
                    last_result = ?
                WHERE selector_id = ?
                ''', (
                    current_date,
                    dkim_key,
                    current_date if dns_check_needed else existing['last_dns_check'],
                    key_creation_date,
                    age_days,
                    dns_exists,
                    True,  # Still active since we just saw it
                    pass_count,
                    fail_count,
                    result,
                    existing['selector_id']
                ))
                
            else:
                # Insert new record
                # For new records, key creation date is now
                key_creation_date = current_date
                age_days = 0
                
                cursor.execute('''
                INSERT INTO dkim_selectors (
                    domain, selector, dkim_key, first_seen_date, last_seen_date,
                    last_dns_check, key_creation_date, age_days, is_active, dns_exists,
                    total_pass_count, total_fail_count, last_result
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    domain,
                    selector,
                    dkim_key,
                    current_date,
                    current_date,
                    current_date if dns_check_needed else None,
                    key_creation_date,
                    age_days,
                    True,  # Active
                    dns_exists,
                    1 if result.lower() == 'pass' else 0,
                    1 if result.lower() != 'pass' else 0,
                    result
                ))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Error tracking DKIM selector: {str(e)}")
            self.conn.rollback()
            raise
        finally:
            cursor.close()
    
    def update_key_ages(self):
        """
        Update all key ages based on creation dates.
        Call this periodically to keep ages current.
        """
        cursor = self.conn.cursor()
        
        try:
            cursor.execute('''
            SELECT selector_id, key_creation_date 
            FROM dkim_selectors 
            WHERE key_creation_date IS NOT NULL
            ''')
            
            records = cursor.fetchall()
            current_date = datetime.now()
            
            for record in records:
                selector_id = record['selector_id']
                creation_date = datetime.fromisoformat(record['key_creation_date'])
                age_days = (current_date - creation_date).days
                
                cursor.execute('''
                UPDATE dkim_selectors 
                SET age_days = ? 
                WHERE selector_id = ?
                ''', (age_days, selector_id))
            
            self.conn.commit()
            return len(records)
        
        except Exception as e:
            print(f"Error updating key ages: {str(e)}")
            self.conn.rollback()
            return 0
    
    def process_dmarc_report(self, report_data: Dict[str, Any]):
        """
        Process a DMARC report to track all DKIM selectors.
        
        Args:
            report_data: Parsed DMARC report data
        """
        report_metadata = report_data.get('report_metadata', {})
        report_id = report_metadata.get('report_id', 'unknown')
        
        for record in report_data.get('records', []):
            auth_results = record.get('auth_results', {})
            
            # Process DKIM records
            for dkim_result in auth_results.get('dkim', []):
                domain = dkim_result.get('domain')
                selector = dkim_result.get('selector')
                result = dkim_result.get('result', 'unknown')
                
                if domain and selector:
                    self.track_dkim_selector(domain, selector, result, report_id)
        
        # Update key ages after processing
        self.update_key_ages()
    
    def get_all_selectors(self, domain: Optional[str] = None, active_only: bool = False) -> List[Dict]:
        """
        Get all DKIM selectors from the database.
        
        Args:
            domain: Optional domain filter
            active_only: Whether to return only active selectors
            
        Returns:
            List of DKIM selector records as dictionaries
        """
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM dkim_selectors"
        conditions = []
        params = []
        
        if domain:
            conditions.append("domain = ?")
            params.append(domain)
        
        if active_only:
            conditions.append("is_active = 1")
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY domain, selector"
        
        cursor.execute(query, params)
        
        return [dict(row) for row in cursor.fetchall()]
    
    def find_old_keys(self, age_threshold_days: int = 180) -> List[Dict]:
        """
        Find DKIM keys that are older than the threshold.
        
        Args:
            age_threshold_days: Age threshold in days
            
        Returns:
            List of old DKIM selector records
        """
        # First update all ages to ensure they're current
        self.update_key_ages()
        
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT * FROM dkim_selectors
        WHERE age_days >= ? AND is_active = 1
        ORDER BY age_days DESC
        ''', (age_threshold_days,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def mark_inactive_selectors(self, days_threshold: int = 30):
        """
        Mark selectors as inactive if they haven't been seen recently.
        
        Args:
            days_threshold: Number of days of inactivity before marking as inactive
        """
        cursor = self.conn.cursor()
        
        # Calculate cutoff date
        cutoff_date = (datetime.now() - timedelta(days=days_threshold)).isoformat()
        
        cursor.execute('''
        UPDATE dkim_selectors
        SET is_active = 0
        WHERE last_seen_date < ? AND is_active = 1
        ''', (cutoff_date,))
        
        updated = cursor.rowcount
        self.conn.commit()
        
        return updated
    
    def print_selectors_summary(self, domain: Optional[str] = None):
        """
        Print a summary of DKIM selectors.
        
        Args:
            domain: Optional domain filter
        """
        # Update ages before display
        self.update_key_ages()
        
        selectors = self.get_all_selectors(domain)
        
        print("\n===== DKIM Selectors Summary =====")
        
        if not selectors:
            print(f"No DKIM selectors found for domain: {domain or 'any'}")
            return
        
        current_domain = None
        
        for sel in selectors:
            # Print domain header when domain changes
            if current_domain != sel['domain']:
                current_domain = sel['domain']
                print(f"\nDomain: {current_domain}")
            
            pass_rate = 0
            total = sel['total_pass_count'] + sel['total_fail_count']
            if total > 0:
                pass_rate = round(sel['total_pass_count'] / total * 100, 2)
            
            dns_status = "✓ DNS Record Found" if sel['dns_exists'] else "✗ No DNS Record"
            active_status = "Active" if sel['is_active'] else "Inactive"
            
            print(f"  Selector: {sel['selector']}")
            print(f"    Status: {active_status}, {dns_status}")
            print(f"    Age: {sel['age_days']} days (Created: {sel.get('key_creation_date', 'unknown')[:10]})")
            print(f"    First seen: {sel['first_seen_date'][:10]}, Last seen: {sel['last_seen_date'][:10]}")
            print(f"    Pass Rate: {pass_rate}% ({sel['total_pass_count']}/{total})")
            
            if sel['dkim_key']:
                # Truncate long DKIM keys for display
                key_display = sel['dkim_key']
                if len(key_display) > 60:
                    key_display = key_display[:57] + "..."
                print(f"    DKIM Key: {key_display}")
            
            print()
    
    def print_old_selectors(self, age_threshold_days: int = 180):
        """
        Print a summary of old DKIM selectors.
        
        Args:
            age_threshold_days: Age threshold in days
        """
        old_selectors = self.find_old_keys(age_threshold_days)
        
        print(f"\n===== Old DKIM Selectors (>{age_threshold_days} days) =====")
        
        if not old_selectors:
            print(f"No DKIM selectors older than {age_threshold_days} days found")
            return
        
        for sel in old_selectors:
            print(f"Domain: {sel['domain']}, Selector: {sel['selector']}")
            print(f"  Age: {sel['age_days']} days (Created: {sel.get('key_creation_date', 'unknown')[:10]})")
            print(f"  Last seen: {sel['last_seen_date'][:10]}")
            print()
    
    def export_to_json(self, filename: str, domain: Optional[str] = None):
        """
        Export selector data to JSON file.
        
        Args:
            filename: Output filename
            domain: Optional domain filter
        """
        # Update ages before export
        self.update_key_ages()
        
        selectors = self.get_all_selectors(domain)
        
        # Convert SQLite Row objects to dicts for JSON serialization
        json_compatible = []
        for selector in selectors:
            row_dict = dict(selector)
            # Convert any non-serializable types
            for key, value in row_dict.items():
                if isinstance(value, datetime):
                    row_dict[key] = value.isoformat()
            json_compatible.append(row_dict)
        
        with open(filename, 'w') as f:
            json.dump(json_compatible, f, indent=2, default=str)
        
        print(f"Exported {len(selectors)} selector records to {filename}")
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()


# Example usage
if __name__ == "__main__":
    import sys
    
    try:
        from enhanced_dmarc_parser import parse_dmarc_report
    except ImportError:
        print("To use this script, make sure the parser module is in the Python path")
        print("Usage: python dkim_selector_tracker.py <dmarc_report.xml>")
        sys.exit(1)
    
    if len(sys.argv) < 2:
        print("Usage: python dkim_selector_tracker.py <dmarc_report.xml>")
        sys.exit(1)
    
    report_file = sys.argv[1]
    tracker = DkimSelectorTracker('dkim_selectors.db')
    
    try:
        # Parse and process report
        print(f"Processing report: {report_file}")
        report_data = parse_dmarc_report(report_file)
        
        tracker.process_dmarc_report(report_data)
        
        # Print summaries
        tracker.print_selectors_summary()
        
        # Print old selectors (more than 180 days)
        tracker.print_old_selectors(180)
        
        # Export to JSON
        tracker.export_to_json('dkim_selectors.json')
        
    except Exception as e:
        print(f"Error: {str(e)}")
    
    finally:
        tracker.close()