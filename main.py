#!/usr/bin/env python3
"""
DMARC Parser and Analyzer - Main Entry Point

This script processes DMARC reports and stores the results in databases.
It integrates the parser with domain statistics and DKIM selector tracking.
"""

import os
import sys
import argparse
import glob
from datetime import datetime


def setup_argparse():
    """Set up command line argument parsing."""
    parser = argparse.ArgumentParser(
        description='DMARC Report Parser and Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Process a single report:
    python main.py -f data_source/sample_dmarc_report.xml
    
  Process all reports in a directory:
    python main.py -d data_source/
    
  Process reports and disable DNS lookups:
    python main.py -d data_source/ --no-dns
        '''
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-f', '--file', help='Path to a single DMARC report file')
    input_group.add_argument('-d', '--directory', help='Path to directory containing DMARC reports')
    
    parser.add_argument('--no-dns', action='store_true', help='Disable DNS lookups for DKIM selectors')
    parser.add_argument('--output', help='Directory to save output files', default='.')
    parser.add_argument('--db-path', help='Directory to store database files', default='.')
    parser.add_argument('--summary', action='store_true', help='Print summary after processing')
    parser.add_argument('--export-json', action='store_true', help='Export results to JSON files')
    
    return parser


def process_file(file_path, domain_tracker, dkim_tracker, do_dns_lookup=True):
    """Process a single DMARC report file."""
    try:
        # Import parser - use relative import based on script location
        from parser.enhanced_dmarc_parser import parse_dmarc_report
        
        print(f"Processing: {file_path}")
        
        # Parse the report
        report_data = parse_dmarc_report(file_path)
        
        # Store in domain stats database
        domain_tracker.process_dmarc_report(report_data)
        
        # Store DKIM selectors (with or without DNS lookup)
        if not do_dns_lookup:
            # Monkey patch the lookup method to skip DNS queries
            original_lookup = dkim_tracker.lookup_dkim_record
            dkim_tracker.lookup_dkim_record = lambda domain, selector: (False, None)
            
        dkim_tracker.process_dmarc_report(report_data)
        
        # Restore original method if we patched it
        if not do_dns_lookup:
            dkim_tracker.lookup_dkim_record = original_lookup
        
        return True
        
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return False


def main():
    """Main entry point."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Import trackers - use relative imports based on script location
    try:
        from parser.domain_stats_tracker import DomainStatsTracker
        from parser.dkim_selector_tracker import DkimSelectorTracker
    except ImportError as e:
        print(f"Error importing required modules: {str(e)}")
        print("Make sure the parser modules are in the correct location.")
        sys.exit(1)
    
    # Ensure db_path exists
    os.makedirs(args.db_path, exist_ok=True)
    
    # Initialize database connections
    domain_db_path = os.path.join(args.db_path, 'dmarc_domain_stats.db')
    dkim_db_path = os.path.join(args.db_path, 'dkim_selectors.db')
    
    domain_tracker = DomainStatsTracker(domain_db_path)
    dkim_tracker = DkimSelectorTracker(dkim_db_path)
    
    try:
        processed_count = 0
        error_count = 0
        
        # Process single file
        if args.file:
            if os.path.isfile(args.file):
                success = process_file(args.file, domain_tracker, dkim_tracker, not args.no_dns)
                if success:
                    processed_count += 1
                else:
                    error_count += 1
            else:
                print(f"Error: File not found - {args.file}")
                sys.exit(1)
        
        # Process directory
        elif args.directory:
            if not os.path.isdir(args.directory):
                print(f"Error: Directory not found - {args.directory}")
                sys.exit(1)
                
            # Find all potential DMARC report files
            xml_files = glob.glob(os.path.join(args.directory, '*.xml'))
            gz_files = glob.glob(os.path.join(args.directory, '*.xml.gz'))
            zip_files = glob.glob(os.path.join(args.directory, '*.zip'))
            
            all_files = xml_files + gz_files + zip_files
            
            if not all_files:
                print(f"No DMARC report files found in {args.directory}")
                sys.exit(1)
            
            print(f"Found {len(all_files)} potential DMARC report files")
            
            # Process each file
            for file_path in all_files:
                success = process_file(file_path, domain_tracker, dkim_tracker, not args.no_dns)
                if success:
                    processed_count += 1
                else:
                    error_count += 1
        
        # Print summary
        print(f"\nProcessed {processed_count} reports with {error_count} errors")
        
        if args.summary:
            print("\n=== Domain Statistics Summary ===")
            domain_tracker.print_domain_stats(limit=10)
            
            print("\n=== DKIM Selectors Summary ===")
            dkim_tracker.print_selectors_summary()
        
        # Export to JSON if requested
        if args.export_json:
            os.makedirs(args.output, exist_ok=True)
            
            domain_json = os.path.join(args.output, 'domain_stats.json')
            dkim_json = os.path.join(args.output, 'dkim_selectors.json')
            
            # Export domain stats
            domain_stats = domain_tracker.get_domain_stats()
            import json
            with open(domain_json, 'w') as f:
                json.dump(domain_stats, f, indent=2, default=str)
            
            # Export DKIM selectors
            dkim_tracker.export_to_json(dkim_json)
            
            print(f"\nExported data to {domain_json} and {dkim_json}")
        
    except KeyboardInterrupt:
        print("\nProcess interrupted by user")
    except Exception as e:
        print(f"\nError: {str(e)}")
    finally:
        # Close database connections
        domain_tracker.close()
        dkim_tracker.close()


if __name__ == "__main__":
    main()