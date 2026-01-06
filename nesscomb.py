#!/usr/bin/env python3
"""
Nessus File Combiner and Interim Vulnerability Report Generator

Useful for creating a single .nessus file for import to other systems like Piperine
and provide early ranking of issues across multiple scans to help when in the middle of a pen test.

This script:
1. Combines multiple .nessus files into a single valid .nessus file
2. Generates a vulnerability report aggregating affected hosts

Campbell Murray 2026
Sodium Cyber Ltd
MIT Licensed
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import csv
from collections import defaultdict
from datetime import datetime
import argparse


class NessusCombiner:
    """Combines multiple .nessus files into one and generates reports."""
    
    SEVERITY_MAP = {
        '0': 'Info',
        '1': 'Low',
        '2': 'Medium',
        '3': 'High',
        '4': 'Critical'
    }
    
    def __init__(self, input_dir, output_dir):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def combine_nessus_files(self):
        """Combine all .nessus files into a single file."""
        print("Combining .nessus files...")
        
        nessus_files = list(self.input_dir.glob("*.nessus"))
        if not nessus_files:
            print("No .nessus files found in input directory!")
            return None
            
        print(f"Found {len(nessus_files)} .nessus files")
        
        # Parse the first file as a template
        first_file = nessus_files[0]
        print(f"Using {first_file.name} as template...")
        tree = ET.parse(first_file)
        root = tree.getroot()
        
        # Find or create Report element
        report = root.find('Report')
        if report is None:
            report = ET.SubElement(root, 'Report')
            report.set('name', 'Combined Report')
        
        # Track existing hosts to avoid duplicates
        existing_hosts = set()
        for host in report.findall('ReportHost'):
            host_name = host.get('name')
            if host_name:
                existing_hosts.add(host_name)
        
        # Process remaining files
        for nessus_file in nessus_files[1:]:
            print(f"Processing {nessus_file.name}...")
            try:
                file_tree = ET.parse(nessus_file)
                file_root = file_tree.getroot()
                file_report = file_root.find('Report')
                
                if file_report is not None:
                    # Add all ReportHost elements
                    for host in file_report.findall('ReportHost'):
                        host_name = host.get('name')
                        if host_name not in existing_hosts:
                            report.append(host)
                            existing_hosts.add(host_name)
                        else:
                            # Merge report items from duplicate host
                            existing_host = report.find(f"ReportHost[@name='{host_name}']")
                            if existing_host is not None:
                                for item in host.findall('ReportItem'):
                                    existing_host.append(item)
            except Exception as e:
                print(f"Error processing {nessus_file.name}: {e}")
                continue
        
        # Write combined file
        output_file = self.output_dir / "combined.nessus"
        print(f"Writing combined file to {output_file}...")
        tree.write(output_file, encoding='UTF-8', xml_declaration=True)
        print(f"Combined file created: {output_file}")
        
        return tree
    
    def generate_vulnerability_report(self, tree=None):
        """Generate vulnerability report aggregating hosts."""
        print("\nGenerating vulnerability report...")
        
        if tree is None:
            # Read the combined file
            combined_file = self.output_dir / "combined.nessus"
            if not combined_file.exists():
                print("Combined file not found. Run combine first.")
                return
            tree = ET.parse(combined_file)
        
        root = tree.getroot()
        report = root.find('Report')
        
        if report is None:
            print("No Report element found!")
            return
        
        # Structure: {plugin_id: {vulnerability_data, hosts: [host_list]}}
        vulnerabilities = defaultdict(lambda: {
            'hosts': [],
            'severity': 'Info',
            'severity_num': 0,
            'plugin_name': '',
            'plugin_id': '',
            'cve': [],
            'cvss': '',
            'description': '',
            'solution': '',
            'synopsis': ''
        })
        
        # Parse all hosts and their vulnerabilities
        host_count = 0
        item_count = 0
        
        for report_host in report.findall('ReportHost'):
            host_name = report_host.get('name', 'Unknown')
            host_count += 1
            
            # Get host properties
            host_ip = host_name
            host_fqdn = ''
            
            for tag in report_host.findall('.//tag'):
                if tag.get('name') == 'host-ip':
                    host_ip = tag.text or host_ip
                elif tag.get('name') == 'host-fqdn':
                    host_fqdn = tag.text or ''
            
            # Process vulnerabilities for this host
            for item in report_host.findall('ReportItem'):
                item_count += 1
                severity = item.get('severity', '0')
                severity_num = int(severity)
                
                # Filter for Critical, High, Medium (severity >= 2)
                if severity_num < 2:
                    continue
                
                plugin_id = item.get('pluginID', 'Unknown')
                plugin_name = item.get('pluginName', 'Unknown')
                
                vuln = vulnerabilities[plugin_id]
                
                # Store vulnerability metadata (if not already stored)
                if not vuln['plugin_name']:
                    vuln['plugin_id'] = plugin_id
                    vuln['plugin_name'] = plugin_name
                    vuln['severity'] = self.SEVERITY_MAP.get(severity, 'Unknown')
                    vuln['severity_num'] = severity_num
                    
                    # Extract detailed information
                    for child in item:
                        if child.tag == 'description':
                            vuln['description'] = (child.text or '')[:500]  # Truncate for report
                        elif child.tag == 'solution':
                            vuln['solution'] = (child.text or '')[:500]
                        elif child.tag == 'synopsis':
                            vuln['synopsis'] = (child.text or '')[:200]
                        elif child.tag == 'cve':
                            if child.text:
                                vuln['cve'].append(child.text)
                        elif child.tag == 'cvss_base_score':
                            vuln['cvss'] = child.text or ''
                
                # Add this host to the affected hosts list
                host_display = host_fqdn if host_fqdn else host_ip
                if host_display not in vuln['hosts']:
                    vuln['hosts'].append(host_display)
        
        print(f"Processed {host_count} hosts with {item_count} vulnerability findings")
        print(f"Found {len(vulnerabilities)} unique medium/high/critical vulnerabilities")
        
        # Generate CSV report
        self._generate_csv_report(vulnerabilities)
        
        # Generate HTML report
        self._generate_html_report(vulnerabilities)
        
    def _generate_csv_report(self, vulnerabilities):
        """Generate CSV vulnerability report."""
        csv_file = self.output_dir / "vulnerability_report.csv"
        print(f"Writing CSV report to {csv_file}...")
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Plugin ID', 'Vulnerability', 'Severity', 'CVSS', 'CVE',
                'Affected Hosts Count', 'Affected Hosts', 'Synopsis', 'Solution'
            ])
            
            # Sort by severity (highest first) then by host count
            sorted_vulns = sorted(
                vulnerabilities.items(),
                key=lambda x: (-x[1]['severity_num'], -len(x[1]['hosts']))
            )
            
            for plugin_id, vuln in sorted_vulns:
                writer.writerow([
                    vuln['plugin_id'],
                    vuln['plugin_name'],
                    vuln['severity'],
                    vuln['cvss'],
                    ', '.join(vuln['cve']) if vuln['cve'] else 'N/A',
                    len(vuln['hosts']),
                    ', '.join(vuln['hosts']),
                    vuln['synopsis'],
                    vuln['solution']
                ])
        
        print(f"CSV report created: {csv_file}")
    
    def _generate_html_report(self, vulnerabilities):
        """Generate HTML vulnerability report."""
        html_file = self.output_dir / "vulnerability_report.html"
        print(f"Writing HTML report to {html_file}...")
        
        # Sort by severity (highest first) then by host count
        sorted_vulns = sorted(
            vulnerabilities.items(),
            key=lambda x: (-x[1]['severity_num'], -len(x[1]['hosts']))
        )
        
        # Count by severity
        severity_counts = defaultdict(int)
        for _, vuln in vulnerabilities.items():
            severity_counts[vuln['severity']] += 1
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        .summary {{
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-box {{
            flex: 1;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}
        .critical {{ background-color: #dc3545; color: white; }}
        .high {{ background-color: #fd7e14; color: white; }}
        .medium {{ background-color: #ffc107; color: black; }}
        .summary-box h3 {{
            margin: 0;
            font-size: 2em;
        }}
        .summary-box p {{
            margin: 5px 0 0 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #007bff;
            color: white;
            font-weight: bold;
            position: sticky;
            top: 0;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity-badge {{
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            display: inline-block;
        }}
        .hosts-list {{
            max-height: 100px;
            overflow-y: auto;
            font-size: 0.9em;
        }}
        .description {{
            max-width: 400px;
            font-size: 0.9em;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Nessus Interim Vulnerability Report</h1>
        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        
        <div class="summary">
            <div class="summary-box critical">
                <h3>{severity_counts.get('Critical', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-box high">
                <h3>{severity_counts.get('High', 0)}</h3>
                <p>High</p>
            </div>
            <div class="summary-box medium">
                <h3>{severity_counts.get('Medium', 0)}</h3>
                <p>Medium</p>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Plugin ID</th>
                    <th>Vulnerability</th>
                    <th>CVSS</th>
                    <th>CVE</th>
                    <th>Hosts (#)</th>
                    <th>Affected Hosts</th>
                    <th>Synopsis</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for plugin_id, vuln in sorted_vulns:
            severity_class = vuln['severity'].lower()
            hosts_html = '<br>'.join(vuln['hosts'][:20])  # Show first 20 hosts only, plenty to find PoC evidence.
            if len(vuln['hosts']) > 20:
                hosts_html += f'<br><em>...and {len(vuln["hosts"]) - 20} more</em>'
            
            cve_list = ', '.join(vuln['cve'][:5]) if vuln['cve'] else 'N/A'
            if len(vuln['cve']) > 5:
                cve_list += f' (+{len(vuln["cve"]) - 5} more)'
            
            html_content += f"""
                <tr>
                    <td><span class="severity-badge {severity_class}">{vuln['severity']}</span></td>
                    <td>{vuln['plugin_id']}</td>
                    <td><strong>{vuln['plugin_name']}</strong></td>
                    <td>{vuln['cvss'] or 'N/A'}</td>
                    <td>{cve_list}</td>
                    <td><strong>{len(vuln['hosts'])}</strong></td>
                    <td class="hosts-list">{hosts_html}</td>
                    <td class="description">{vuln['synopsis']}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML report created: {html_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Combine Nessus files and generate vulnerability reports'
    )
    parser.add_argument(
        '--input-dir',
        default='input',
        help='Input directory containing .nessus files (default: input)'
    )
    parser.add_argument(
        '--output-dir',
        default='output',
        help='Output directory for combined file and reports (default: output)'
    )
    parser.add_argument(
        '--combine-only',
        action='store_true',
        help='Only combine files, do not generate reports'
    )
    parser.add_argument(
        '--report-only',
        action='store_true',
        help='Only generate reports from existing combined file'
    )
    
    args = parser.parse_args()
    
    combiner = NessusCombiner(args.input_dir, args.output_dir)
    
    if args.report_only:
        combiner.generate_vulnerability_report()
    elif args.combine_only:
        combiner.combine_nessus_files()
    else:
        # Do both
        tree = combiner.combine_nessus_files()
        if tree:
            combiner.generate_vulnerability_report(tree)
    
    print("\n✅ Done!")


if __name__ == '__main__':
    main()

