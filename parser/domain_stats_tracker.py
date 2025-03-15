import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional
import json


class DomainStatsTracker:
    """
    Track domain-level DMARC authentication statistics.
    """
    
    def __init__(self, db_path: str = 'dmarc_domain_stats.db'):
        """
        Initialize the domain statistics tracker.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
    
    def _create_tables(self):
        """Create the necessary database tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Domain stats table - stores aggregated statistics per domain per reporting period
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_stats (
            stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,                    -- Domain these statistics are for
            report_id TEXT NOT NULL,                 -- Report these statistics are from
            reporting_org TEXT,                      -- Organization that sent the report
            report_begin_date TEXT,                  -- Start of reporting period
            report_end_date TEXT,                    -- End of reporting period
            total_messages INTEGER DEFAULT 0,        -- Total message count
            passing_dkim INTEGER DEFAULT 0,          -- Messages passing DKIM
            passing_spf INTEGER DEFAULT 0,           -- Messages passing SPF
            failing_dkim INTEGER DEFAULT 0,          -- Messages failing DKIM
            failing_spf INTEGER DEFAULT 0,           -- Messages failing SPF
            dkim_pass_pct REAL DEFAULT 0,            -- DKIM pass percentage
            spf_pass_pct REAL DEFAULT 0,             -- SPF pass percentage
            disposition_none INTEGER DEFAULT 0,      -- Messages with 'none' disposition
            disposition_quarantine INTEGER DEFAULT 0, -- Messages quarantined
            disposition_reject INTEGER DEFAULT 0,     -- Messages rejected
            created_date TEXT,                       -- When this record was created
            UNIQUE(domain, report_id)
        )
        ''')
        
        # Create index on domain for faster lookups
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_domain_stats_domain ON domain_stats(domain)
        ''')
        
        self.conn.commit()
        cursor.close()
    
    def process_dmarc_report(self, report_data: Dict[str, Any]):
        """
        Process a DMARC report and store domain-level statistics.
        
        Args:
            report_data: Parsed DMARC report data
        """
        # Extract report metadata
        report_metadata = report_data.get('report_metadata', {})
        report_id = report_metadata.get('report_id', 'unknown')
        reporting_org = report_metadata.get('org_name', 'unknown')
        
        # Extract date range
        date_range = report_metadata.get('date_range', {})
        begin_dt = date_range.get('begin', {}).get('datetime')
        end_dt = date_range.get('end', {}).get('datetime')
        
        begin_date = begin_dt.isoformat() if begin_dt else None
        end_date = end_dt.isoformat() if end_dt else None
        
        # Track stats by domain
        domain_stats = {}
        
        # Process each record
        for record in report_data.get('records', []):
            row = record.get('row', {})
            identifiers = record.get('identifiers', {})
            policy_evaluated = row.get('policy_evaluated', {})
            
            # Get domain and count
            domain = identifiers.get('header_from', 'unknown')
            count = int(row.get('count', 0))
            
            # Initialize domain stats if not already
            if domain not in domain_stats:
                domain_stats[domain] = {
                    'total_messages': 0,
                    'passing_dkim': 0,
                    'passing_spf': 0,
                    'failing_dkim': 0,
                    'failing_spf': 0,
                    'disposition_none': 0,
                    'disposition_quarantine': 0,
                    'disposition_reject': 0
                }
            
            # Update message count
            domain_stats[domain]['total_messages'] += count
            
            # Update authentication results
            dkim_result = policy_evaluated.get('dkim', '')
            spf_result = policy_evaluated.get('spf', '')
            
            if dkim_result == 'pass':
                domain_stats[domain]['passing_dkim'] += count
            else:
                domain_stats[domain]['failing_dkim'] += count
                
            if spf_result == 'pass':
                domain_stats[domain]['passing_spf'] += count
            else:
                domain_stats[domain]['failing_spf'] += count
            
            # Update disposition counts
            disposition = policy_evaluated.get('disposition', 'none')
            if disposition == 'none':
                domain_stats[domain]['disposition_none'] += count
            elif disposition == 'quarantine':
                domain_stats[domain]['disposition_quarantine'] += count
            elif disposition == 'reject':
                domain_stats[domain]['disposition_reject'] += count
        
        # Store domain stats in database
        self._store_domain_stats(
            domain_stats, 
            report_id, 
            reporting_org, 
            begin_date, 
            end_date
        )
    
    def _store_domain_stats(self, domain_stats: Dict[str, Dict], 
                           report_id: str, 
                           reporting_org: str, 
                           begin_date: Optional[str], 
                           end_date: Optional[str]):
        """
        Store domain statistics in the database.
        
        Args:
            domain_stats: Dictionary of domain statistics
            report_id: DMARC report ID
            reporting_org: Organization that sent the report
            begin_date: Start of reporting period
            end_date: End of reporting period
        """
        cursor = self.conn.cursor()
        created_date = datetime.now().isoformat()
        
        try:
            for domain, stats in domain_stats.items():
                # Calculate percentages
                total = stats['total_messages']
                dkim_pass_pct = 0
                spf_pass_pct = 0
                
                if total > 0:
                    dkim_pass_pct = round(stats['passing_dkim'] / total * 100, 2)
                    spf_pass_pct = round(stats['passing_spf'] / total * 100, 2)
                
                # Check if record already exists
                cursor.execute('''
                SELECT stat_id FROM domain_stats 
                WHERE domain = ? AND report_id = ?
                ''', (domain, report_id))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing record
                    cursor.execute('''
                    UPDATE domain_stats SET
                        total_messages = ?,
                        passing_dkim = ?,
                        passing_spf = ?,
                        failing_dkim = ?,
                        failing_spf = ?,
                        dkim_pass_pct = ?,
                        spf_pass_pct = ?,
                        disposition_none = ?,
                        disposition_quarantine = ?,
                        disposition_reject = ?
                    WHERE stat_id = ?
                    ''', (
                        stats['total_messages'],
                        stats['passing_dkim'],
                        stats['passing_spf'],
                        stats['failing_dkim'],
                        stats['failing_spf'],
                        dkim_pass_pct,
                        spf_pass_pct,
                        stats['disposition_none'],
                        stats['disposition_quarantine'],
                        stats['disposition_reject'],
                        existing['stat_id']
                    ))
                else:
                    # Insert new record
                    cursor.execute('''
                    INSERT INTO domain_stats (
                        domain, report_id, reporting_org, 
                        report_begin_date, report_end_date,
                        total_messages, passing_dkim, passing_spf,
                        failing_dkim, failing_spf, 
                        dkim_pass_pct, spf_pass_pct,
                        disposition_none, disposition_quarantine, disposition_reject,
                        created_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        domain, report_id, reporting_org,
                        begin_date, end_date,
                        stats['total_messages'],
                        stats['passing_dkim'],
                        stats['passing_spf'],
                        stats['failing_dkim'],
                        stats['failing_spf'],
                        dkim_pass_pct,
                        spf_pass_pct,
                        stats['disposition_none'],
                        stats['disposition_quarantine'],
                        stats['disposition_reject'],
                        created_date
                    ))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Error storing domain stats: {str(e)}")
            self.conn.rollback()
            raise
    
    def get_domain_stats(self, domain: Optional[str] = None, 
                         start_date: Optional[str] = None, 
                         end_date: Optional[str] = None) -> List[Dict]:
        """
        Get domain statistics from the database.
        
        Args:
            domain: Optional domain filter
            start_date: Optional start date filter (ISO format)
            end_date: Optional end date filter (ISO format)
            
        Returns:
            List of domain statistics records
        """
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM domain_stats"
        conditions = []
        params = []
        
        if domain:
            conditions.append("domain = ?")
            params.append(domain)
        
        if start_date:
            conditions.append("report_end_date >= ?")
            params.append(start_date)
        
        if end_date:
            conditions.append("report_begin_date <= ?")
            params.append(end_date)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY domain, report_begin_date DESC"
        
        cursor.execute(query, params)
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_domain_summary(self, domain: str, days: int = 30) -> Dict:
        """
        Get a summary of domain statistics over a period.
        
        Args:
            domain: Domain to summarize
            days: Number of days to include
            
        Returns:
            Dictionary with summary statistics
        """
        cutoff_date = (datetime.now() - datetime.timedelta(days=days)).isoformat()
        
        cursor = self.conn.cursor()
        
        cursor.execute('''
        SELECT 
            SUM(total_messages) AS total_messages,
            SUM(passing_dkim) AS passing_dkim,
            SUM(passing_spf) AS passing_spf,
            SUM(failing_dkim) AS failing_dkim,
            SUM(failing_spf) AS failing_spf,
            SUM(disposition_none) AS disposition_none,
            SUM(disposition_quarantine) AS disposition_quarantine,
            SUM(disposition_reject) AS disposition_reject
        FROM 
            domain_stats
        WHERE 
            domain = ? AND
            report_end_date >= ?
        ''', (domain, cutoff_date))
        
        row = cursor.fetchone()
        
        if not row or row['total_messages'] is None:
            return {
                'domain': domain,
                'total_messages': 0,
                'dkim_pass_pct': 0,
                'spf_pass_pct': 0,
                'dispositions': {'none': 0, 'quarantine': 0, 'reject': 0}
            }
        
        summary = dict(row)
        summary['domain'] = domain
        
        # Calculate percentages
        if summary['total_messages'] > 0:
            summary['dkim_pass_pct'] = round(summary['passing_dkim'] / summary['total_messages'] * 100, 2)
            summary['spf_pass_pct'] = round(summary['passing_spf'] / summary['total_messages'] * 100, 2)
        else:
            summary['dkim_pass_pct'] = 0
            summary['spf_pass_pct'] = 0
        
        # Format dispositions
        summary['dispositions'] = {
            'none': summary.pop('disposition_none', 0),
            'quarantine': summary.pop('disposition_quarantine', 0),
            'reject': summary.pop('disposition_reject', 0)
        }
        
        return summary
    
    def print_domain_stats(self, domain: Optional[str] = None, limit: int = 10):
        """
        Print domain statistics in a readable format.
        
        Args:
            domain: Optional domain filter
            limit: Maximum number of records to print
        """
        stats = self.get_domain_stats(domain=domain)
        
        if not stats:
            print(f"No statistics found for domain: {domain or 'any'}")
            return
        
        print("\n===== Domain Authentication Statistics =====")
        
        current_domain = None
        count = 0
        
        for stat in stats:
            if count >= limit:
                break
                
            if current_domain != stat['domain']:
                current_domain = stat['domain']
                print(f"\nDomain: {current_domain}")
                count += 1
            
            print(f"  Report ID: {stat['report_id']}")
            print(f"  Period: {stat['report_begin_date']} to {stat['report_end_date']}")
            print(f"  Total Messages: {stat['total_messages']}")
            print(f"  DKIM Pass: {stat['dkim_pass_pct']}% ({stat['passing_dkim']}/{stat['total_messages']})")
            print(f"  SPF Pass: {stat['spf_pass_pct']}% ({stat['passing_spf']}/{stat['total_messages']})")
            print(f"  Dispositions: none={stat['disposition_none']}, quarantine={stat['disposition_quarantine']}, reject={stat['disposition_reject']}")
            print()
    
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
        # Direct import might not work depending on the file structure
        print("To use this script, make sure the parser module is in the Python path")
        print("Usage: python domain_stats_tracker.py <dmarc_report.xml>")
        sys.exit(1)
    
    if len(sys.argv) < 2:
        print("Usage: python domain_stats_tracker.py <dmarc_report.xml>")
        sys.exit(1)
    
    report_file = sys.argv[1]
    tracker = DomainStatsTracker('dmarc_domain_stats.db')
    
    try:
        # Parse and process report
        print(f"Processing report: {report_file}")
        report_data = parse_dmarc_report(report_file)
        
        tracker.process_dmarc_report(report_data)
        
        # Print statistics
        tracker.print_domain_stats()
        
    except Exception as e:
        print(f"Error: {str(e)}")
    
    finally:
        tracker.close()