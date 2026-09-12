import random
import re
import json

class SAIIEngine:
    """
    Semantic Attack-Intent Inference (SAII) Engine.
    Simulates a hybrid feature engineering + ML model that predicts the 
    intent of a URL rather than the specific attack type.
    """

    # --- PHISHING KEYWORDS AND BRANDS (used for the generic pattern) ---
    PHISHING_KEYWORDS = ['login', 'secure', 'account', 'verify', 'billing', 'support', 'password-reset', 'auth', 'portal', 'invoice', 'security', 'pay', 'order', 'coupon', 'track', 'parcel']
    BRANDS = ['rnicrosoft', 'netflx', 'bkmyshw', 'ubm', 'chtgt', 'gugle', 'amzn', 'amazn', 'meesho', 'myntra', 'msft', 'openai', 'gmail', 'office365', 'bookmyshow', 'ibm', 'chatgpt', 'google', 'amazon', 'fedex', 'dhl', 'usps']
    PHISHING_PATTERN_GENERIC = r'(' + '|'.join(BRANDS) + r').*(' + '|'.join(PHISHING_KEYWORDS) + r')'
    
    # --- 100 USER-PROVIDED SYNTHETIC PHISHING URLS (for explicit training) ---
    EXPLICIT_PHISHING_PATTERNS = [
        r'login-rnicrosoft-secure-01\[\.\]example', r'account-rnicrosoft-portal-02\[\.\]example', r'rnicrosoft-support-03\[\.\]example', r'office-rnicrosoft-verify-04\[\.\]example', r'rnicrosoft-auth-05\[\.\]example', r'secure-rnicrosoft-login-06\[\.\]example', r'rnicrosoft-account-check-07\[\.\]example', r'verify-rnicrosoft-08\[\.\]example', r'msft-login-09\[\.\]example', r'office365-rnicrosoft-10\[\.\]example', r'rnicrosoft-portal-11\[\.\]example', r'billing-rnicrosoft-12\[\.\]example', r'netflx-login-01\[\.\]example', r'secure-netflx-02\[\.\]example', r'netflx-account-03\[\.\]example', r'verify-netflx-04\[\.\]example', r'subscription-netflx-05\[\.\]example', r'netflx-premium-06\[\.\]example', r'netflx-pay-07\[\.\]example', r'netflx-support-08\[\.\]example', r'netflx-billing-09\[\.\]example', r'netflx-verify-10\[\.\]example', r'bkmyshw-login-01\[\.\]example', r'bkmyshw-pay-02\[\.\]example', r'bkmyshw-account-03\[\.\]example', r'bkmyshw-ticket-04\[\.\]example', r'verify-bkmyshw-05\[\.\]example', r'secure-bkmyshw-06\[\.\]example', r'bkmyshw-support-07\[\.\]example', r'bkmyshw-payments-08\[\.\]example', r'ubm-login-01\[\.\]example', r'secure-ubm-02\[\.\]example', r'ubm-cloud-auth-03\[\.\]example', r'ubm-support-04\[\.\]example', r'ubm-account-05\[\.\]example', r'verify-ubm-06\[\.\]example', r'chtgt-login-01\[\.\]example', r'openai-chtgt-02\[\.\]example', r'chtgt-access-03\[\.\]example', r'chtgt-subscribe-04\[\.\]example', r'chtgt-billing-05\[\.\]example', r'gugle-login-01\[\.\]example', r'accounts-gugle-secure-02\[\.\]example', r'gugle-verify-03\[\.\]example', r'gugle-account-04\[\.\]example', r'gugle-security-05\[\.\]example', r'gmail-gugle-06\[\.\]example', r'amzn-login-01\[\.\]example', r'secure-amzn-02\[\.\]example', r'amzn-account-03\[\.\]example', r'amazn-pay-04\[\.\]example', r'amzn-prime-05\[\.\]example', r'verify-amzn-06\[\.\]example', r'meesho-login-01\[\.\]example', r'meesho-account-02\[\.\]example', r'meesho-pay-03\[\.\]example', r'verify-meesho-04\[\.\]example', r'secure-meesho-05\[\.\]example', r'myntra-login-01\[\.\]example', r'myntra-account-02\[\.\]example', r'myntra-pay-03\[\.\]example', r'verify-myntra-04\[\.\]example', r'myntra-offer-05\[\.\]example', r'google-secure-mail-07\[\.\]example', r'amazon-verify-payment-07\[\.\]example', r'netflix-customer-care-11\[\.\]example', r'msft-account-security-13\[\.\]example', r'chatgpt-pro-06\[\.\]example', r'ibm-enterprise-login-08\[\.\]example', r'bms-ticket-09\[\.\]example', r'meesho-seller-06\[\.\]example', r'myntra-fashion-offer-06\[\.\]example', r'google-drive-verify-08\[\.\]example', r'amazon-invoice-08\[\.\]example', r'netflix-password-reset-12\[\.\]example', r'msft-update-14\[\.\]example', r'openai-payment-07\[\.\]example', r'ibm-payroll-09\[\.\]example', r'bookmyshow-wallet-10\[\.\]example', r'meesho-login-07\[\.\]example', r'myntra-coupon-07\[\.\]example', r'google-security-alert-09\[\.\]example', r'amazon-account-check-09\[\.\]example', r'netflix-confirm-13\[\.\]example', r'microsoft-security-update-15\[\.\]example', r'chatgpt-account-08\[\.\]example', r'ibm-corp-portal-10\[\.\]example', r'bookmyshow-support-11\[\.\]example', r'meesho-order-08\[\.\]example', r'myntra-auth-08\[\.\]example', r'google-auth-10\[\.\]example', r'amazon-prime-verify-10\[\.\]example', r'netflix-account-update-14\[\.\]example', r'microsoft-billing-16\[\.\]example', r'chatgpt-security-09\[\.\]example', r'ibm-documentation-11\[\.\]example', r'bms-verify-12\[\.\]example', r'meesho-cashback-09\[\.\]example', r'myntra-order-09\[\.\]example', r'google-login-secure-11\[\.\]example'
    ]
    # -------------------------------------------------------------------

    INTENTS = {
        # --- NEW HIGH-RISK INTENTS ---

        # 1. NTRO VULNS (Critical Core Exploitation, e.g., Log4j, Shellshock)
        "high_risk_cve": {
            "risk": 0.99,
            "patterns": [
                r'\${jndi:ldap:\/\/', # Log4j-like JNDI injection (CVE-2021-44228)
                r'\%20\&\&\%20',      # Command injection via URL-encoded characters (CVE-2025-9001-like)
                r'goform/WifiGuestSet\?shareSpeed=A{200,}', # Buffer Overflow (CVE-2025-12225-like)
                r'xp_cmdshell',      # SQL Server RCE
                r'document\.location\.replace\(', # High-risk XSS/Session Hijack attempt
                r'cmd\.exe'          # Windows command execution
            ]
        },
        
        # 2. MOBILE/SMS SPAM (Smishing/Banking Phishing/App Downloads)
        "mobile_sms_spam": {
            "risk": 0.92,
            "patterns": [
                r'\/\w{4,6}$',        # Short URLs (e.g., bit.ly/xxxx, t.ly/yyyy)
                r'package\s*track',   # Package tracking spam
                r'bank\s*alert',      # Banking alert spam
                r'mobile\s*app\s*download', # App download links
                r'urgent\s*payment',   # High-pressure language (simulated via URL)
                r'whatsapp\s*update'   # Social/Messaging phishing
            ]
        },

        # --- EXISTING CORE ATTACK INTENTS ---
        
        # 3. CREDENTIAL PHISHING (HIGH RISK)
        "credential_phishing": {
            "risk": 0.88, 
            "patterns": EXPLICIT_PHISHING_PATTERNS + [PHISHING_PATTERN_GENERIC]
        },
        
        # 4. DATABASE MANIPULATION (SQLi)
        "database_manipulation": {
            "risk": 0.93,
            "patterns": [
                r'\'\s*(or|and)\s*1=1', r'union\s+select', r'information_schema', 
                r'xp_cmdshell', r'cast\(', r'sysobjects'
            ]
        },
        
        # 5. EXECUTE SCRIPT CLIENT (XSS)
        "execute_script_client": {
            "risk": 0.89,
            "patterns": [
                r'<script', r'javascript:', r'onerror', r'onload', r'&lt;s', r'%3cscript', r'onmouse',
                r'alert\(', r'document\.cookie', r'prompt\(', r'confirm\(', r'img\s+src', r'iframe'
            ]
        },
        
        # 6. ESCALATE PRIVILEGES (LFI/Traversal)
        "escalate_privileges": {"risk": 0.95, "patterns": [r'\.\./', r'etc/passwd', r'boot\.ini', r'web\.xml', r'%2e%2e%2f', r'proc/self/cwd']},
        
        # 7. EXECUTE SUBSYSTEM CMD (RCE/Command Injection)
        "execute_subsystem_cmd": {"risk": 0.90, "patterns": [r'cmd=', r'exec=', r'\&c=', r'system\(', r'shell_exec', r'%26%26', r';', r'\`', r'\$\(']},
        
        # 8. MODIFY AUTH STATE (Session Hijack/CSRF)
        "modify_auth_state": {"risk": 0.75, "patterns": [r'session=', r'cookie=', r'jwt=', r'sessionid', r'auth_token', r'setcookie']},
        
        # 9. PROBE OR ENUMERATE (Scanning)
        "probe_or_enumerate": {"risk": 0.60, "patterns": [r'/admin/', r'/backup', r'/test\.php', r'robots\.txt', r'/fuzz', r'sqlmap', r'nmap']},
        
        # 10. CROSS-SITE REQUEST FORGERY (CSRF)
        "cross_site_request_forgery": {"risk": 0.70, "patterns": [r'auth_action=delete', r'auth_action=update', r'confirm=true', r'csrf_token=false', r'action=add_user', r'http_referrer']}, 
        
        # 11. ROUTER DEVICE EXPLOIT (IoT Vulns)
        "router_device_exploit": {"risk": 0.98, "patterns": [r'tenda', r'goform/', r'diag\.html', r'reboot\.cgi', r'boaform', r'/login\.asp', r'syscmd']}, 
        
        # 12. BENIGN (Normal Traffic)
        "benign": {"risk": 0.05, "patterns": []}
    }
    
    EXPLANATIONS = {
        # NEW EXPLANATIONS
        "high_risk_cve": "CRITICAL: The URL contains patterns associated with extremely high-risk, wide-scale vulnerabilities (e.g., JNDI/Log4j or known remote buffer overflows) targeting core systems.",
        "mobile_sms_spam": "HIGH: This URL utilizes a short URL or contains keywords associated with Smishing (SMS phishing) or fraudulent package/banking alerts, highly common in mobile attacks.",
        
        # EXISTING EXPLANATIONS
        "credential_phishing": "The URL matches a specific synthetic phishing campaign (brand/keyword combination) designed to steal user credentials. HIGH CONFIDENCE.",
        "database_manipulation": "The URL contains classic patterns (e.g., boolean logic, UNION operator) associated with SQL Injection attacks.",
        "execute_script_client": "The URL contains common script tags, functions, or event handlers, indicative of Cross-Site Scripting (XSS).",
        "escalate_privileges": "This URL exhibits patterns of deep path traversal or access to restricted OS files (LFI/RFI).",
        "execute_subsystem_cmd": "Suspicious shell operators or command keywords suggest an attempt to execute commands on the server (RCE/Command Injection).",
        "modify_auth_state": "The query string targets authentication or session-related parameters, indicating an attempt to modify the user's state.",
        "probe_or_enumerate": "This request accesses common administrative or sensitive resource paths, typical of vulnerability scanning or enumeration.",
        "cross_site_request_forgery": "The URL structure mimics a state-changing action (e.g., delete, update) that could lead to a CSRF attack.",
        "router_device_exploit": "High-risk patterns matching known router/IoT device exploit vectors or firmware endpoints (e.g., Tenda, D-Link).",
        "benign": "The URL structure is normal and aligns with expected application behavior."
    }

    def analyze_url(self, url):
        """
        Analyzes a URL to infer its Semantic Attack Intent (SAII).
        """
        if not url:
            return {"error": "URL cannot be empty."}

        url_lower = url.lower()
        
        best_intent = "benign"
        max_confidence = random.uniform(0.01, 0.15) 
        explanation = self.EXPLANATIONS["benign"]
        
        for intent, data in self.INTENTS.items():
            if intent == "benign":
                continue

            is_match = False
            for pattern in data["patterns"]:
                # Added check for presence of [.] (common way to represent phishing URL)
                pattern_to_search = pattern.replace('\[\.\]', '.') 
                
                # Check for short URL length indicator, only for mobile_sms_spam
                if intent == "mobile_sms_spam" and re.search(r'\/\w{4,6}$', url_lower) and len(url_lower) < 30:
                     is_match = True
                     break
                
                if re.search(pattern_to_search, url_lower):
                    is_match = True
                    break

            if is_match:
                # Confidence calculation is based on the inherent risk score of the intent
                confidence = data["risk"] + random.uniform(-0.1, 0.05)
                confidence = max(0.5, min(0.99, confidence)) 

                if confidence > max_confidence:
                    max_confidence = confidence
                    best_intent = intent
                    explanation = self.EXPLANATIONS[intent]
        
        if max_confidence >= 0.95:
            severity = "CRITICAL"
            color = "var(--critical-red)"
        elif max_confidence >= 0.8:
            severity = "HIGH"
            color = "var(--high-orange)"
        elif max_confidence >= 0.6:
            severity = "MEDIUM"
            color = "var(--medium-yellow)"
        else:
            severity = "LOW"
            color = "var(--low-green)"

        # Final formatting
        return {
            "intent": best_intent.replace('_', ' ').title(),
            "confidence": round(max_confidence * 100, 2),
            "severity": severity,
            "color": color,
            "semantic_signals": {
                "traversal_segments": url_lower.count('../') + url_lower.count('%2e%2e%2f'),
                "script_operators": url_lower.count('<') + url_lower.count('>') + url_lower.count('(') + url_lower.count(')'),
                # Updated shell operators to include command separators specific to RCE/NTRO vulns
                "shell_operators": len(re.findall(r'%26%26|%3b|%24|;|\`|jndi|exec|cmd', url_lower))
            },
            "explanation": explanation
        }