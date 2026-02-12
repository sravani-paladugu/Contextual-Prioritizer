import re

# ==============================================================================
# ENTERPRISE SECURITY DOMAINS
# ==============================================================================
# This matrix defines the "Exploitation Chains." 
# If a SAST bug exists alongside a DAST exposure in the same domain, it is a P0.
DOMAINS = {
    "DATA_EXFILTRATION": {
        "sast_cwes": ["89", "90", "564", "200", "548", "915"], 
        "dast_shields": ["942", "615", "497", "264", "200"],
        "impact": "Data Breach / Database Injection"
    },
    "CLIENT_SIDE_INTEGRITY": {
        "sast_cwes": ["79", "601", "352", "1021", "353", "1333"],
        "dast_shields": ["693", "933", "829", "16"],
        "impact": "Account Takeover / Session Hijacking"
    },
    "INFRA_SECRET_EXPOSURE": {
        "sast_cwes": ["798", "259", "321"],
        "dast_shields": ["615", "548", "16", "200", "0"],
        "impact": "Administrative / Infrastructure Takeover"
    }
}

def parse_fuzzy(filename):
    """Robustly extracts CWEs and full line data from the cleaned text files."""
    results = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                # Extracts the number after 'CWE-'
                cwe_match = re.search(r'CWE-(\d+)', line)
                if cwe_match:
                    cwe_id = cwe_match.group(1)
                    if cwe_id not in results:
                        results[cwe_id] = line.strip()
    except FileNotFoundError:
        print(f"[-] ERROR: {filename} not found. Please run cleaner.py first.")
    return results

def run_analysis():
    sast_map = parse_fuzzy('semgrep_clean.txt')
    dast_map = parse_fuzzy('dast_clean.txt')

    if not sast_map and not dast_map:
        print("[-] No data found to analyze.")
        return

    print("\n" + "="*95)
    print("                 ENTERPRISE SECURITY CONTEXTUAL PRIORITIZATION")
    print("="*95)

    p0_matches = []
    correlated_sast = set()
    correlated_dast = set()

    # --------------------------------------------------------------------------
    # PRIORITY 0: CONTEXTUAL MATCHES
    # --------------------------------------------------------------------------
    print(f"\n[!] PRIORITY 0: CRITICAL (UNPROTECTED EXPLOITABLE PATHS)")
    print("-" * 95)
    
    for domain, config in DOMAINS.items():
        active_sast = [c for c in config['sast_cwes'] if c in sast_map]
        active_dast = [c for c in config['dast_shields'] if c in dast_map]

        if active_sast and active_dast:
            for s in active_sast:
                for d in active_dast:
                    match_entry = {
                        "domain": domain,
                        "s_line": sast_map[s],
                        "d_line": dast_map[d],
                        "impact": config['impact'],
                        "s_id": s,
                        "d_id": d
                    }
                    p0_matches.append(match_entry)
                    correlated_sast.add(s)
                    correlated_dast.add(d)
                    
                    print(f">>> [MATCH: {domain}]")
                    print(f"    - SOURCE BUG: {match_entry['s_line']}")
                    print(f"    - EXPOSURE:   {match_entry['d_line']}")
                    print(f"    - IMPACT:     {match_entry['impact']}\n")

    if not p0_matches:
        print("    No Cross-Tool correlations found.")

    # --------------------------------------------------------------------------
    # PRIORITY 1: DAST ONLY
    # --------------------------------------------------------------------------
    print(f"\n[?] PRIORITY 1: ACTIVE ATTACK SURFACE (DAST ONLY)")
    print("-" * 95)
    p1_count = 0
    for cwe, raw_text in dast_map.items():
        if cwe not in correlated_dast:
            print(f"    - {raw_text}")
            p1_count += 1

    # --------------------------------------------------------------------------
    # PRIORITY 2: SAST ONLY
    # --------------------------------------------------------------------------
    print(f"\n[-] PRIORITY 2: SOURCE CODE BACKLOG (SAST ONLY)")
    print("-" * 95)
    p2_count = 0
    for cwe, raw_text in sast_map.items():
        if cwe not in correlated_sast:
            print(f"    - {raw_text}")
            p2_count += 1

    # --------------------------------------------------------------------------
    # HIGH-LEVEL EXECUTIVE SUMMARY
    # --------------------------------------------------------------------------
    print("\n" + "="*95)
    print("                          EXECUTIVE RISK SUMMARY")
    print("="*95)
    
    total_unique_sast = len(sast_map)
    total_unique_dast = len(dast_map)
    
    # Identify unique CWE IDs that contributed to P0 matches
    unique_p0_cwes = sorted(list(correlated_sast.union(correlated_dast)), key=int)
    
    print(f"[*] Total Unique CWEs Identified: {total_unique_sast + total_unique_dast}")
    print(f"    - From Semgrep (Code):      {total_unique_sast}")
    print(f"    - From ZAP (Live Site):     {total_unique_dast}")
    print(f"\n[!] INTELLIGENT NOISE REDUCTION:")
    print(f"    By correlating code bugs with live environmental exposures, we have")
    print(f"    narrowed your immediate focus to {len(unique_p0_cwes)} Critical CWE IDs.")
    print(f"    Addressing these will break {len(p0_matches)} active attack chains.")
    
    print(f"\n[>] ACTIONABLE CWEs TO FIX: {', '.join(['CWE-'+i for i in unique_p0_cwes])}")
    print("="*95 + "\n")

if __name__ == "__main__":
    run_analysis()
