Contextual Prioritizer:
A Contextual Prioritizer is a security intelligence tool designed to solve the "Alert Fatigue" crisis in modern software development. While traditional scanners (SAST/DAST) flag thousands of theoretical vulnerabilities, a Contextual Prioritizer filters these results based on runtime reality—identifying which flaws are actually reachable and exploitable in a live environment.

**The Core Problem: Static Noise**

Traditional security tools are often "context-blind." They analyze code in isolation:

SAST (Static Analysis): Flags a vulnerable library simply because it exists in the codebase, even if that code is never actually executed.

DAST (Dynamic Analysis): Flags an exposed endpoint without knowing if the underlying code is sensitive or if it has existing protections.

This leads to a "Critical Alert" backlog where developers waste 70% of their time investigating false positives or "dead code" vulnerabilities that pose zero actual risk to the business.

**Step 1: Run OWASP Juice Shop Locally**
Juice Shop is a Node.js application. We will use Docker because it’s the most consistent way to ensure all dependencies (like the SQLite database) are set up correctly.

docker pull bkimminich/juice-shop

docker run --rm -d -p 8081:3000 --name juiceshop bkimminich/juice-shop

 URL to load: http://vdi-lsddp-034:8081

If needed: docker stop juiceshop.

**Step 2: Generate SAST/DAST Data:**
Clone the Juice Shop Code (to scan it):

git clone https://github.com/juice-shop/juice-shop.git --depth 1
cd juice-shop
Static Application Security Testing (SAST)
SAST analyzes the source code, byte code, or binaries without executing the app. It finds "potential" vulnerabilities in the logic.

**Tools to use:**
Semgrep (Highly Recommended): Fast, open-source, and has excellent rules for JavaScript/Node.js.

   SAST Scanning: docker run --rm -v `pwd`:/src returntocorp/semgrep semgrep scan --config auto --json --output semgrep_results.json

Dynamic Application Security Testing (DAST)
DAST interacts with your running Juice Shop instance (the one on http://vdi-lsddp-034:8081) to find vulnerabilities like a real hacker would.

Tools to use:
OWASP ZAP (Zaproxy): The gold standard for open-source DAST.

How to generate the data:
You can run an automated "Baseline Scan" using the OWASP ZAP Docker container. Since Juice Shop is on your VM, you can point ZAP at it:

docker run --rm --network host -i ghcr.io/zaproxy/zaproxy:stable zap.sh 
-cmd -quickurl http://vdi-lsddp-034:8081 >> dast_results.json
Why this matters for your Prioritizer: DAST confirms if a vulnerability is actually reachable over the network. If SAST finds a bug but DAST can't hit it, the priority drops.

**Step 3: Cleaning up .json files:**
clean_semgrep(input_file)
This function processes results from Semgrep,

Severity Mapping: It converts Semgrep's internal labels (ERROR, WARNING, INFO) into a more standard corporate risk format (e.g., 3 (High)).

Data Extraction: It drills deep into the JSON structure (specifically extra -> metadata -> cwe) to find the CWE (Common Weakness Enumeration) identifier.

Regex Logic: It uses re.search(r'CWE-(\d+)', cwe_str) to extract just the number from a string like "CWE-89: SQL Injection".

Output: It sorts all findings by their CWE ID and saves them to semgrep_clean.txt.

clean_dast(input_file)
This function processes results from OWASP ZAP, a DAST tool that scans your running website.

XML Parsing via Regex: Instead of using a standard XML library, it uses Regular Expressions (re.findall and re.search) to find <alertitem> blocks. This makes it more resilient if the XML file is slightly malformed or contains non-standard characters.

HTML Stripping: DAST reports often include HTML formatting in descriptions. The line re.sub('<[^<]+?>', '', ...) uses regex to "strip" those tags so you get plain text.

Filtering: It ignores any findings where the CWE ID is -1 (ZAP's way of saying it couldn't map the alert to a specific weakness).

Output: Similar to the Semgrep function, it sorts the results and creates a formatted table in dast_clean.txt.

**Step 4: The Contextual Prioritizer Code**
The  primary purpose of the script is to act as an "intelligence layer" that combines two different types of security data to find the most dangerous risks.

In a large company, security teams often have thousands of bugs. This script uses a Contextual Correlation logic to tell them which bugs to fix first.

1. The Core Logic: 
At the top of the script is the DOMAINS dictionary. This is the most important part. It groups vulnerabilities not by their ID number, but by their Attack Surface.

sast_cwes: Vulnerabilities found in the source code (the "Sword").

dast_shields: Missing security configurations on the live server (the "Broken Shield").

Correlation: If the script finds a "Sword" and a "Broken Shield" in the same category (e.g., CLIENT_SIDE_INTEGRITY), it promotes that finding to Priority 0 (Critical).

2. The Data Input: parse_fuzzy(filename)
This function reads the "cleaned" text files you generated earlier.

Robustness: It uses Regular Expressions (re.search(r'CWE-(\d+)')) to find the CWE number regardless of how the rest of the line is formatted.

Deduplication: It uses a dictionary (results) to ensure that if the same CWE appears 10 times in a file, it only stores it once, keeping the report concise.

3. The Analysis Engine: run_analysis()
This is the "Brain" of the script. It performs a three-tier prioritization:

 Tier 0: The "Perfect Storm" (Critical)
The script loops through the DOMAINS map. It looks for a match where:

A code bug from Semgrep belongs to a domain.

AND an exposure from DAST belongs to that same domain.

   Result: These are flagged as "Unprotected Exploitable Paths" because the server's defenses are down exactly where the code is weak.

Tier 1: Surface Exposure (Medium/High)
These are findings from the DAST (ZAP) scanner that didn't correlate to a specific code bug. These are still dangerous because they represent the "Active Attack Surface" visible to hackers.

Tier 2: The Backlog (Low/Medium)
These are code bugs from Semgrep that appear to be "shielded" (meaning DAST didn't find an easy way to exploit them yet). These go into the long-term fix-it list.

4. The Executive Risk Summary
The final section of the code provides a "Bottom Line" for management, showing that instead of fixing 50 things, they can achieve maximum security by focusing on a specific handful of CWE IDs.

It counts how many total bugs were found.

It identifies the unique list of "Actionable CWEs."

**Step 5: How to Run and Test**
python3 cleaner_v2.py → generates semgrep_clean.txt and dast_clean.txt

Successfully created semgrep_clean.txt
Successfully created dast_clean.txt

The above two files are passed as inputs to python3 prioritizer_3.py

Output:
                 ENTERPRISE SECURITY CONTEXTUAL PRIORITIZATION
[!] PRIORITY 0: CRITICAL (UNPROTECTED EXPLOITABLE PATHS)
-----------------------------------------------------------------------------------------------
>>> [MATCH: DATA_EXFILTRATION]
    - SOURCE BUG: CWE-89   | 3 (High)     | data/static/codefixes/dbSchemaChallenge_1.ts:5
    - EXPOSURE:   CWE-615  | 0          | Information Disclosure - Suspicious Comments
    - IMPACT:     Data Breach / Database Injection

>>> [MATCH: DATA_EXFILTRATION]
    - SOURCE BUG: CWE-89   | 3 (High)     | data/static/codefixes/dbSchemaChallenge_1.ts:5
    - EXPOSURE:   CWE-497  | 1          | Timestamp Disclosure - Unix
    - IMPACT:     Data Breach / Database Injection

>>> [MATCH: DATA_EXFILTRATION]
    - SOURCE BUG: CWE-89   | 3 (High)     | data/static/codefixes/dbSchemaChallenge_1.ts:5
    - EXPOSURE:   CWE-264  | 2          | Cross-Domain Misconfiguration
    - IMPACT:     Data Breach / Database Injection

>>> [MATCH: DATA_EXFILTRATION]
    - SOURCE BUG: CWE-548  | 2 (Medium)   | server.ts:269
    - EXPOSURE:   CWE-615  | 0          | Information Disclosure - Suspicious Comments
    - IMPACT:     Data Breach / Database Injection

>>> [MATCH: DATA_EXFILTRATION]
    - SOURCE BUG: CWE-548  | 2 (Medium)   | server.ts:269
    - EXPOSURE:   CWE-497  | 1          | Timestamp Disclosure - Unix
    - IMPACT:     Data Breach / Database Injection


[?] PRIORITY 1: ACTIVE ATTACK SURFACE (DAST ONLY)
-----------------------------------------------------------------------------------------------

[-] PRIORITY 2: SOURCE CODE BACKLOG (SAST ONLY)
-----------------------------------------------------------------------------------------------
    - CWE-73   | 2 (Medium)   | routes/fileServer.ts:33
    - CWE-95   | 2 (Medium)   | routes/captcha.ts:23
    - CWE-134  | 1 (Low)      | server.ts:155
    - CWE-611  | 2 (Medium)   | routes/fileUpload.ts:83
    - CWE-1104 | 2 (Medium)   | routes/b2bOrder.ts:23
                          EXECUTIVE RISK SUMMARY

[*] Total Unique CWEs Identified: 20
    - From Semgrep (Code):      14
    - From ZAP (Live Site):     6

[!] INTELLIGENT NOISE REDUCTION:
    By correlating code bugs with live environmental exposures, we have
    narrowed your immediate focus to 15 Critical CWE IDs.
    Addressing these will break 21 active attack chains.

[>] ACTIONABLE CWEs TO FIX: CWE-0, CWE-79, CWE-89, CWE-264, CWE-321, CWE-353, CWE-497, CWE-548, CWE-601, CWE-615, CWE-693, CWE-798, CWE-829, CWE-915, CWE-1333


 
