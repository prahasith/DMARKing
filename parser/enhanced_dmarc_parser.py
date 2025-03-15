import xml.etree.ElementTree as ET
import gzip
import zipfile
import json
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict

def parse_dmarc_report(file_path: str) -> Dict[str, Any]:
    """
    Parse a DMARC aggregate report XML file, supporting both raw and compressed formats.
    
    Args:
        file_path: Path to the DMARC report file (.xml, .xml.gz, or .zip)
        
    Returns:
        Dictionary containing structured DMARC report data
    """
    try:
        # Determine file type and parse accordingly
        if file_path.endswith('.gz'):
            with gzip.open(file_path, 'rb') as f:
                tree = ET.parse(f)
                root = tree.getroot()
        elif file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path) as z:
                # Assume the first XML file in the archive is the report
                xml_files = [f for f in z.namelist() if f.endswith('.xml')]
                if not xml_files:
                    raise ValueError(f"No XML files found in ZIP archive: {file_path}")
                with z.open(xml_files[0]) as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
        else:
            # Assume regular XML file
            tree = ET.parse(file_path)
            root = tree.getroot()
        
        # Initialize result dictionary
        result = {
            'policy_published': {},
            'records': [],
            'report_metadata': {}
        }
        
        # Parse policy_published section
        policy_published = root.find('policy_published')
        if policy_published is not None:
            for element in ['domain', 'adkim', 'aspf', 'p', 'sp', 'pct', 'fo']:
                elem = policy_published.find(element)
                if elem is not None and elem.text is not None:
                    result['policy_published'][element] = elem.text
        
        # Parse records
        records = root.findall('record')
        for record in records:
            record_data = {'row': {}, 'identifiers': {}, 'auth_results': {'dkim': [], 'spf': []}}
            
            # Parse row data
            row = record.find('row')
            if row is not None:
                for element in ['source_ip', 'count']:
                    elem = row.find(element)
                    if elem is not None and elem.text is not None:
                        record_data['row'][element] = elem.text
                
                # Parse policy_evaluated
                policy_evaluated = row.find('policy_evaluated')
                if policy_evaluated is not None:
                    record_data['row']['policy_evaluated'] = {}
                    for element in ['disposition', 'dkim', 'spf']:
                        elem = policy_evaluated.find(element)
                        if elem is not None and elem.text is not None:
                            record_data['row']['policy_evaluated'][element] = elem.text
                    
                    # Parse reasons if present
                    reasons = policy_evaluated.findall('reason')
                    if reasons:
                        record_data['row']['policy_evaluated']['reasons'] = []
                        for reason in reasons:
                            reason_data = {}
                            for element in ['type', 'comment']:
                                elem = reason.find(element)
                                if elem is not None and elem.text is not None:
                                    reason_data[element] = elem.text
                            record_data['row']['policy_evaluated']['reasons'].append(reason_data)
            
            # Parse identifiers
            identifiers = record.find('identifiers')
            if identifiers is not None:
                for element in ['header_from', 'envelope_from', 'envelope_to']:
                    elem = identifiers.find(element)
                    if elem is not None and elem.text is not None:
                        record_data['identifiers'][element] = elem.text
            
            # Parse auth_results
            auth_results = record.find('auth_results')
            if auth_results is not None:
                # Handle multiple DKIM results
                for dkim_result in auth_results.findall('dkim'):
                    dkim_data = {}
                    for element in ['domain', 'result', 'selector']:
                        elem = dkim_result.find(element)
                        if elem is not None and elem.text is not None:
                            dkim_data[element] = elem.text
                    record_data['auth_results']['dkim'].append(dkim_data)
                
                # Handle multiple SPF results
                for spf_result in auth_results.findall('spf'):
                    spf_data = {}
                    for element in ['domain', 'result', 'scope']:
                        elem = spf_result.find(element)
                        if elem is not None and elem.text is not None:
                            spf_data[element] = elem.text
                    record_data['auth_results']['spf'].append(spf_data)
            
            result['records'].append(record_data)
        
        # Parse report_metadata
        report_metadata = root.find('report_metadata')
        if report_metadata is not None:
            for element in ['org_name', 'email', 'extra_contact_info', 'report_id']:
                elem = report_metadata.find(element)
                if elem is not None and elem.text is not None:
                    result['report_metadata'][element] = elem.text
            
            # Parse date_range
            date_range = report_metadata.find('date_range')
            if date_range is not None:
                result['report_metadata']['date_range'] = {}
                begin = date_range.find('begin')
                end = date_range.find('end')
                
                if begin is not None and begin.text is not None:
                    timestamp = int(begin.text)
                    result['report_metadata']['date_range']['begin'] = {
                        'timestamp': timestamp,
                        'datetime': datetime.fromtimestamp(timestamp)
                    }
                
                if end is not None and end.text is not None:
                    timestamp = int(end.text)
                    result['report_metadata']['date_range']['end'] = {
                        'timestamp': timestamp,
                        'datetime': datetime.fromtimestamp(timestamp)
                    }
        
        return result
    
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML format in {file_path}: {str(e)}")
    except (IOError, OSError) as e:
        raise IOError(f"Error reading file {file_path}: {str(e)}")
    except Exception as e:
        raise Exception(f"Error parsing DMARC report {file_path}: {str(e)}")


def analyze_by_domain(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze DMARC report data grouped by sender domains.
    
    Args:
        report_data: Parsed DMARC report data
        
    Returns:
        Dictionary containing analysis by domain
    """
    domain_stats = defaultdict(lambda: {
        'total_messages': 0,
        'passing_dkim': 0,
        'passing_spf': 0,
        'failing_dkim': 0,
        'failing_spf': 0,
        'source_ips': set(),
        'dispositions': defaultdict(int)
    })
    
    for record in report_data.get('records', []):
        row = record.get('row', {})
        identifiers = record.get('identifiers', {})
        auth_results = record.get('auth_results', {})
        policy_evaluated = row.get('policy_evaluated', {})
        
        # Get the domain from header_from (primary identifier in DMARC)
        sender_domain = identifiers.get('header_from', 'unknown')
        count = int(row.get('count', 0))
        source_ip = row.get('source_ip')
        
        # Update domain statistics
        domain_stats[sender_domain]['total_messages'] += count
        
        if source_ip:
            domain_stats[sender_domain]['source_ips'].add(source_ip)
        
        # Track policy evaluation results
        dkim_result = policy_evaluated.get('dkim', '')
        spf_result = policy_evaluated.get('spf', '')
        
        if dkim_result == 'pass':
            domain_stats[sender_domain]['passing_dkim'] += count
        else:
            domain_stats[sender_domain]['failing_dkim'] += count
            
        if spf_result == 'pass':
            domain_stats[sender_domain]['passing_spf'] += count
        else:
            domain_stats[sender_domain]['failing_spf'] += count
        
        # Track disposition counts by domain
        disposition = policy_evaluated.get('disposition', 'none')
        domain_stats[sender_domain]['dispositions'][disposition] += count
    
    # Convert defaultdicts and sets for JSON serialization
    result = {}
    for domain, stats in domain_stats.items():
        result[domain] = {
            'total_messages': stats['total_messages'],
            'passing_dkim': stats['passing_dkim'],
            'passing_spf': stats['passing_spf'],
            'failing_dkim': stats['failing_dkim'],
            'failing_spf': stats['failing_spf'],
            'source_ips': list(stats['source_ips']),
            'unique_ip_count': len(stats['source_ips']),
            'dispositions': dict(stats['dispositions']),
        }
        
        # Add percentage calculations
        total = stats['total_messages']
        if total > 0:
            result[domain]['dkim_pass_rate'] = round(stats['passing_dkim'] / total * 100, 2)
            result[domain]['spf_pass_rate'] = round(stats['passing_spf'] / total * 100, 2)
    
    return result


def list_all_domains(report_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Extract all domains mentioned in a DMARC report.
    
    Args:
        report_data: Parsed DMARC report data
        
    Returns:
        Dictionary of domain lists by type
    """
    domains = {
        'policy_domain': [],
        'header_from': set(),
        'envelope_from': set(),
        'dkim': set(),
        'spf': set()
    }
    
    # Get the main policy domain
    policy_domain = report_data.get('policy_published', {}).get('domain')
    if policy_domain:
        domains['policy_domain'].append(policy_domain)
    
    # Extract domains from all records
    for record in report_data.get('records', []):
        identifiers = record.get('identifiers', {})
        auth_results = record.get('auth_results', {})
        
        # Get domains from identifiers
        header_from = identifiers.get('header_from')
        if header_from:
            domains['header_from'].add(header_from)
            
        envelope_from = identifiers.get('envelope_from')
        if envelope_from:
            domains['envelope_from'].add(envelope_from)
        
        # Get domains from authentication results
        for dkim_result in auth_results.get('dkim', []):
            dkim_domain = dkim_result.get('domain')
            if dkim_domain:
                domains['dkim'].add(dkim_domain)
                
        for spf_result in auth_results.get('spf', []):
            spf_domain = spf_result.get('domain')
            if spf_domain:
                domains['spf'].add(spf_domain)
    
    # Convert sets to lists for JSON serialization
    domains['header_from'] = list(domains['header_from'])
    domains['envelope_from'] = list(domains['envelope_from'])
    domains['dkim'] = list(domains['dkim'])
    domains['spf'] = list(domains['spf'])
    
    return domains


def print_domain_analysis(domain_analysis: Dict[str, Any]) -> None:
    """
    Print a formatted report of domain-specific DMARC analysis.
    
    Args:
        domain_analysis: Domain analysis dictionary
    """
    print("\n===== DMARC Analysis by Domain =====")
    
    for domain, stats in domain_analysis.items():
        print(f"\nDomain: {domain}")
        print(f"  Total Messages: {stats['total_messages']}")
        print(f"  DKIM Pass Rate: {stats.get('dkim_pass_rate', 0)}%")
        print(f"  SPF Pass Rate: {stats.get('spf_pass_rate', 0)}%")
        print(f"  Unique IPs: {stats['unique_ip_count']}")
        print(f"  Dispositions: {stats['dispositions']}")


def print_domains_list(domains: Dict[str, List[str]]) -> None:
    """
    Print all domains found in the DMARC report.
    
    Args:
        domains: Dictionary of domain lists by type
    """
    print("\n===== Domains in DMARC Report =====")
    print(f"Policy Domain: {', '.join(domains['policy_domain'])}")
    print(f"Header From Domains: {', '.join(domains['header_from'])}")
    print(f"Envelope From Domains: {', '.join(domains['envelope_from'])}")
    print(f"DKIM Domains: {', '.join(domains['dkim'])}")
    print(f"SPF Domains: {', '.join(domains['spf'])}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        # Default file path when no argument is provided
        report_file = '/Users/praha/Desktop/DMARKing/data/sample_dmarc_report.xml'
        print(f"No file specified, using default: {report_file}")
    else:
        report_file = sys.argv[1]
    
    try:
        # Rest of your code remains the same
        print(f"Parsing DMARC report: {report_file}")
        report_data = parse_dmarc_report(report_file)
        
        # List all domains in the report
        domains = list_all_domains(report_data)
        print_domains_list(domains)
        
        # Analyze by domain
        domain_analysis = analyze_by_domain(report_data)
        print_domain_analysis(domain_analysis)
        
        # Save results to JSON files
        with open('domain_list.json', 'w') as f:
            json.dump(domains, f, indent=2)
            
        with open('domain_analysis.json', 'w') as f:
            json.dump(domain_analysis, f, indent=2)
            
        print("\nResults saved to domain_list.json and domain_analysis.json")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

