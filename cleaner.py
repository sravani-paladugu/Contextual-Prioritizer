import json
import re

def clean_semgrep(input_file):
    """Extracts CWE, Name, Description, and Priority from Semgrep JSON."""
    cleaned = []
    # Mapping Semgrep severity to a standard Risk Code format
    priority_map = {
        "ERROR": "3 (High)",
        "WARNING": "2 (Medium)",
        "INFO": "1 (Low)"
    }

    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
            for result in data.get('results', []):
                path = result.get('path')
                line = result.get('start', {}).get('line')
                severity = result.get('extra', {}).get('severity', 'UNKNOWN')
                msg = result.get('extra', {}).get('message', '').strip()
                metadata = result.get('extra', {}).get('metadata', {})
                cwes = metadata.get('cwe', [])
                if isinstance(cwes, str): cwes = [cwes]

                for cwe_str in cwes:
                    cwe_match = re.search(r'CWE-(\d+)', cwe_str)
                    if cwe_match:
                        cleaned.append({
                            'id': cwe_match.group(1),
                            'name': cwe_str.split(':')[-1].strip() if ':' in cwe_str else "N/A",
                            'desc': msg,
                            'risk_code': priority_map.get(severity, severity),
                            'risk_desc': severity,
                            'loc': f"{path}:{line}"
                        })

        cleaned.sort(key=lambda x: int(x['id']))
        with open('semgrep_clean.txt', 'w') as out:
            out.write(f"{'CWEID':<8} | {'Priority':<12} | {'Location / Alert Name'}\n")
            out.write("=" * 100 + "\n")
            for item in cleaned:
                out.write(f"CWE-{item['id']:<4} | {item['risk_code']:<12} | {item['loc']}\n")
                out.write(f"Alert: {item['name']}\n")
                out.write(f"Description: {item['desc'][:150]}...\n")
                out.write("-" * 100 + "\n")
        print("Successfully created semgrep_clean.txt")
    except Exception as e:
        print(f"Error cleaning Semgrep: {e}")

def clean_dast(input_file):
    """Extracts CWEID, Name, Description, Risk Code, and Risk Desc from ZAP XML."""
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Regex to extract each alert block
        alerts = re.findall(r'<alertitem>(.*?)</alertitem>', content, re.DOTALL)
        cleaned = []

        for item in alerts:
            name = re.search(r'<alert>(.*?)</alert>', item)
            risk_code = re.search(r'<riskcode>(.*?)</riskcode>', item)
            risk_desc = re.search(r'<riskdesc>(.*?)</riskdesc>', item)
            desc = re.search(r'<desc>(.*?)</desc>', item)
            cweid = re.search(r'<cweid>(.*?)</cweid>', item)

            if cweid and cweid.group(1) != "-1":
                # Clean HTML tags from description
                clean_desc = re.sub('<[^<]+?>', '', desc.group(1)) if desc else "N/A"
                cleaned.append({
                    'id': cweid.group(1),
                    'name': name.group(1) if name else "N/A",
                    'risk_code': risk_code.group(1) if risk_code else "N/A",
                    'risk_desc': risk_desc.group(1) if risk_desc else "N/A",
                    'desc': clean_desc.strip()
                })

        cleaned.sort(key=lambda x: int(x['id']))
        with open('dast_clean.txt', 'w') as out:
            out.write(f"{'CWEID':<8} | {'Risk Code':<10} | {'Alert Name'}\n")
            out.write("=" * 100 + "\n")
            for item in cleaned:
                out.write(f"CWE-{item['id']:<4} | {item['risk_code']:<10} | {item['name']}\n")
                out.write(f"Risk Desc: {item['risk_desc']}\n")
                out.write(f"Description: {item['desc'][:150]}...\n")
                out.write("-" * 100 + "\n")
        print("Successfully created dast_clean.txt")
    except Exception as e:
        print(f"Error cleaning DAST: {e}")

if __name__ == "__main__":
    clean_semgrep('semgrep_results.json')
    clean_dast('dast_results.json')
