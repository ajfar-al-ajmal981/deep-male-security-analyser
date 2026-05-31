from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
import os
import email
from email import policy
from email.parser import BytesParser
import extract_msg
from datetime import datetime
import re
from urllib.parse import urlparse
import whois
from datetime import datetime
from config import Database
import json
import io
from xml.sax.saxutils import escape


app = Flask(__name__)
app.secret_key = "deepsecure_key"

db = Database()

# PDF Generation
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Configuration


UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml', 'msg'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_urls(text):
    """Extract URLs from text"""
    if not text:
        return []
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return urls


def parse_eml_file(filepath):
    """Parse .eml file and extract components"""
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        # Extract basic info
        subject = msg.get('subject', 'No Subject')
        sender = msg.get('from', 'Unknown')
        recipient = msg.get('to', 'Unknown')
        date = msg.get('date', 'Unknown')
        
        # Extract body
        body_text = ""
        body_html = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif content_type == 'text/html':
                    body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        # Extract URLs
        urls = extract_urls(body_text) + extract_urls(body_html)
        
        # Extract attachments info
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'name': filename,
                            'type': part.get_content_type()
                        })
        
        return {
            'subject': subject,
            'from': sender,
            'to': recipient,
            'date': date,
            'body_text': body_text,
            'body_html': body_html,
            'urls': list(set(urls)),  # Remove duplicates
            'attachments': attachments,
            'headers': dict(msg.items())
        }
    
    except Exception as e:
        raise Exception(f"Error parsing EML file: {str(e)}")


def parse_msg_file(filepath):
    """Parse .msg file and extract components"""
    try:
        msg = extract_msg.Message(filepath)
        
        subject = msg.subject or 'No Subject'
        sender = msg.sender or 'Unknown'
        recipient = msg.to or 'Unknown'
        date = msg.date or 'Unknown'
        body_text = msg.body or ''
        
        # Extract URLs
        urls = extract_urls(body_text)
        
        # Extract attachments
        attachments = []
        if hasattr(msg, 'attachments') and msg.attachments:
            for attachment in msg.attachments:
                attachments.append({
                    'name': attachment.longFilename or attachment.shortFilename,
                    'type': 'unknown'
                })
        
        msg.close()
        
        return {
            'subject': subject,
            'from': sender,
            'to': recipient,
            'date': str(date),
            'body_text': body_text,
            'body_html': '',
            'urls': list(set(urls)),
            'attachments': attachments,
            'headers': {}
        }
    
    except Exception as e:
        raise Exception(f"Error parsing MSG file: {str(e)}")


def parse_pasted_content(content):
    """Parse pasted email content"""
    try:
        lines = content.strip().split('\n')
        
        # Initialize variables
        subject = 'No Subject'
        sender = 'Unknown'
        recipient = 'Unknown'
        date = 'Unknown'
        body_lines = []
        headers_found = False
        
        # Parse headers
        for i, line in enumerate(lines):
            line = line.strip()
            
            if line.lower().startswith('subject:'):
                subject = line.split(':', 1)[1].strip()
                headers_found = True
            elif line.lower().startswith('from:'):
                sender = line.split(':', 1)[1].strip()
                headers_found = True
            elif line.lower().startswith('to:'):
                recipient = line.split(':', 1)[1].strip()
                headers_found = True
            elif line.lower().startswith('date:'):
                date = line.split(':', 1)[1].strip()
                headers_found = True
            elif headers_found and line == '':
                # Empty line after headers, rest is body
                body_lines = lines[i+1:]
                break
        
        # If no headers found, treat entire content as body
        if not headers_found:
            body_lines = lines
        
        body_text = '\n'.join(body_lines)
        
        # Extract URLs
        urls = extract_urls(body_text)
        
        return {
            'subject': subject,
            'from': sender,
            'to': recipient,
            'date': date,
            'body_text': body_text,
            'body_html': '',
            'urls': list(set(urls)),
            'attachments': [],
            'headers': {}
        }
    
    except Exception as e:
        raise Exception(f"Error parsing pasted content: {str(e)}")


def analyze_email(email_data):
    """
    Placeholder function for ML analysis
    Replace this with your actual ML model prediction
    """
    # For now, simple rule-based detection as placeholder
    body = email_data.get('body_text', '').lower()
    subject = email_data.get('subject', '').lower()
    
    # Suspicious keywords
    phishing_keywords = ['verify account', 'suspended', 'urgent action', 'click here', 
                         'confirm identity', 'password', 'social security']
    spam_keywords = ['winner', 'congratulations', 'free money', 'act now', 'limited time']
    
    score = 0
    label = 'safe'
    
    # Check for suspicious keywords
    for keyword in phishing_keywords:
        if keyword in body or keyword in subject:
            score += 20
    
    for keyword in spam_keywords:
        if keyword in body or keyword in subject:
            score += 15
    
    # Check URLs
    if len(email_data.get('urls', [])) > 3:
        score += 15
    
    # Check suspicious attachments
    for attachment in email_data.get('attachments', []):
        name = attachment.get('name', '').lower()
        if name.endswith(('.exe', '.scr', '.bat', '.cmd', '.zip')):
            score += 25
    
    # Determine label based on score
    if score >= 40:
        label = 'phishing'
    elif score >= 25:
        label = 'spam'
    elif score >= 15:
        label = 'scam'
    
    confidence = min(score, 95)
    
    return {
        'label': label,
        'confidence': confidence,
        'score': score
    }


#-------- Comprehensive Analysis Function ---------


# Suspicious keyword lists for feature engineering
URGENT_WORDS = [
    'urgent', 'immediate', 'action required', 'verify', 'suspended', 'locked',
    'expires', 'limited time', 'act now', 'confirm', 'update required',
    'security alert', 'unusual activity', 'click here', 'verify account'
]

FINANCIAL_TERMS = [
    'bank', 'account', 'credit card', 'payment', 'invoice', 'wire transfer',
    'paypal', 'transaction', 'refund', 'money', 'cash', 'prize', 'winner',
    'bitcoin', 'cryptocurrency', 'investment'
]

SUSPICIOUS_PHRASES = [
    'congratulations', 'you have won', 'claim your prize', 'free money',
    'nigerian prince', 'inheritance', 'million dollars', 'tax refund',
    'social security', 'irs', 'amazon', 'apple', 'microsoft'
]

SHORTENED_URL_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
]

DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
    '.jar', '.msi', '.app', '.deb', '.rpm'
]

SUSPICIOUS_EXTENSIONS = [
    '.zip', '.rar', '.7z', '.iso', '.dmg', '.pkg'
]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_urls(text):
    """Extract URLs from text"""
    if not text:
        return []
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return urls


def check_domain_age(domain):
    """Check domain registration age using WHOIS"""
    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            age = (datetime.now() - creation_date).days
            return age
    except:
        return None
    return None


def analyze_url(url, email_body=''):
    """Detailed URL analysis"""
    parsed = urlparse(url)
    domain = parsed.netloc
    
    analysis = {
        'url': url,
        'domain': domain,
        'is_https': parsed.scheme == 'https',
        'is_shortened': any(short in domain for short in SHORTENED_URL_DOMAINS),
        'display_text': None,
        'mismatch': False,
        'risk_level': 'safe'
    }
    
    # Check for URL mismatch in email body
    # Look for <a href="actual_url">display_text</a>
    if email_body:
        pattern = rf'<a[^>]+href=["\']({re.escape(url)})["\'][^>]*>([^<]+)</a>'
        match = re.search(pattern, email_body, re.IGNORECASE)
        if match:
            display_text = match.group(2).strip()
            analysis['display_text'] = display_text
            # Check if display text suggests different domain
            if 'http' in display_text and domain not in display_text:
                analysis['mismatch'] = True
    
    # Risk assessment
    risk_score = 0
    
    if not analysis['is_https']:
        risk_score += 20
    
    if analysis['is_shortened']:
        risk_score += 30
    
    if analysis['mismatch']:
        risk_score += 40
    
    # Check for suspicious patterns in URL
    suspicious_patterns = ['login', 'verify', 'account', 'secure', 'update', 'confirm']
    if any(pattern in url.lower() for pattern in suspicious_patterns):
        risk_score += 15
    
    if risk_score >= 40:
        analysis['risk_level'] = 'malicious'
    elif risk_score >= 20:
        analysis['risk_level'] = 'suspicious'
    
    return analysis


def check_email_authentication(headers):
    """Check SPF, DKIM, DMARC from headers"""
    auth_results = {
        'spf_status': 'unknown',
        'spf_details': 'No SPF record found',
        'dkim_status': 'unknown',
        'dkim_details': 'No DKIM signature found',
        'dmarc_status': 'unknown',
        'dmarc_details': 'No DMARC record found'
    }
    
    # Check Authentication-Results header
    auth_header = headers.get('Authentication-Results', '') or headers.get('authentication-results', '')
    
    if auth_header:
        auth_lower = auth_header.lower()
        
        # SPF Check
        if 'spf=pass' in auth_lower:
            auth_results['spf_status'] = 'pass'
            auth_results['spf_details'] = 'Sender IP authorized'
        elif 'spf=fail' in auth_lower:
            auth_results['spf_status'] = 'fail'
            auth_results['spf_details'] = 'Sender IP not authorized'
        elif 'spf=softfail' in auth_lower:
            auth_results['spf_status'] = 'warning'
            auth_results['spf_details'] = 'Sender IP possibly unauthorized'
        
        # DKIM Check
        if 'dkim=pass' in auth_lower:
            auth_results['dkim_status'] = 'pass'
            auth_results['dkim_details'] = 'Valid signature'
        elif 'dkim=fail' in auth_lower:
            auth_results['dkim_status'] = 'fail'
            auth_results['dkim_details'] = 'Invalid or missing signature'
        
        # DMARC Check
        if 'dmarc=pass' in auth_lower:
            auth_results['dmarc_status'] = 'pass'
            auth_results['dmarc_details'] = 'Domain policy validated'
        elif 'dmarc=fail' in auth_lower:
            auth_results['dmarc_status'] = 'fail'
            auth_results['dmarc_details'] = 'Domain policy violation'
    
    return auth_results


def extract_features(email_data):
    """Advanced feature engineering"""
    body = email_data.get('body_text', '')
    subject = email_data.get('subject', '')
    combined_text = f"{subject} {body}".lower()
    
    features = {
        'text_length': len(body),
        'urgent_words_count': 0,
        'urgent_words_found': [],
        'financial_terms_count': 0,
        'suspicious_phrases_count': 0,
        'capital_ratio': 0,
        'special_chars_count': 0,
        'exclamation_count': body.count('!'),
        'question_count': body.count('?'),
        'has_html': bool(email_data.get('body_html')),
        'spelling_errors': 0,  # Placeholder - would need spell checker
    }
    
    # Count urgent words
    for word in URGENT_WORDS:
        if word in combined_text:
            features['urgent_words_count'] += combined_text.count(word)
            features['urgent_words_found'].append(word)
    
    # Count financial terms
    for term in FINANCIAL_TERMS:
        if term in combined_text:
            features['financial_terms_count'] += 1
    
    # Count suspicious phrases
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in combined_text:
            features['suspicious_phrases_count'] += 1
    
    # Capital letter ratio
    if body:
        capitals = sum(1 for c in body if c.isupper())
        features['capital_ratio'] = round((capitals / len(body)) * 100, 2)
    
    # Special characters
    special_chars = r'[!@#$%^&*()_+=\[\]{};:\'",.<>?/\\|`~]'
    features['special_chars_count'] = len(re.findall(special_chars, body))
    
    return features


def analyze_attachments(attachments):
    """Analyze attachment safety"""
    analyzed = []
    
    for att in attachments:
        name = att.get('name', '').lower()
        att_info = att.copy()
        att_info['is_dangerous'] = False
        att_info['is_suspicious'] = False
        
        # Check for dangerous extensions
        if any(name.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            att_info['is_dangerous'] = True
        
        # Check for suspicious extensions
        elif any(name.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            att_info['is_suspicious'] = True
        
        # Check for double extensions (e.g., invoice.pdf.exe)
        if name.count('.') > 1:
            att_info['is_suspicious'] = True
        
        analyzed.append(att_info)
    
    return analyzed


def detect_red_flags(email_data, features, auth_results, url_analysis, attachments):
    """Detect specific red flags"""
    red_flags = []
    
    # Authentication failures
    if auth_results['spf_status'] == 'fail':
        red_flags.append({
            'type': 'Authentication',
            'message': 'SPF check failed - sender may be spoofed'
        })
    
    if auth_results['dkim_status'] == 'fail':
        red_flags.append({
            'type': 'Authentication',
            'message': 'DKIM signature invalid - email may be forged'
        })
    
    # Sender/Reply-To mismatch
    sender = email_data.get('from', '').lower()
    reply_to = email_data.get('reply_to', '').lower()
    if reply_to and reply_to != sender:
        red_flags.append({
            'type': 'Sender Mismatch',
            'message': f'Reply-To address ({reply_to}) differs from sender ({sender})'
        })
    
    # Urgent language
    if features['urgent_words_count'] >= 3:
        red_flags.append({
            'type': 'Urgent Language',
            'message': f'Contains {features["urgent_words_count"]} urgent/pressure words'
        })
    
    # Suspicious URLs
    malicious_urls = [u for u in url_analysis if u['risk_level'] == 'malicious']
    if malicious_urls:
        red_flags.append({
            'type': 'Malicious URLs',
            'message': f'{len(malicious_urls)} suspicious/malicious URL(s) detected'
        })
    
    # Dangerous attachments
    dangerous_attachments = [a for a in attachments if a.get('is_dangerous')]
    if dangerous_attachments:
        red_flags.append({
            'type': 'Dangerous Attachments',
            'message': f'{len(dangerous_attachments)} potentially dangerous attachment(s) found'
        })
    
    # Generic greeting
    body = email_data.get('body_text', '').lower()
    if any(greeting in body[:100] for greeting in ['dear customer', 'dear user', 'dear member']):
        red_flags.append({
            'type': 'Generic Greeting',
            'message': 'Uses generic greeting instead of your name'
        })
    
    return red_flags


def comprehensive_email_analysis(email_data):
    """Perform comprehensive analysis with all features"""
    
    # Extract features
    features = extract_features(email_data)
    
    # Check email authentication
    auth_results = check_email_authentication(email_data.get('headers', {}))
    
    # Check domain age
    sender_email = email_data.get('from', '')
    domain_match = re.search(r'@([\w\.-]+)', sender_email)
    if domain_match:
        domain = domain_match.group(1)
        domain_age = check_domain_age(domain)
        features['domain_age_days'] = domain_age
    else:
        features['domain_age_days'] = None
    
    # Merge auth results into features
    features.update(auth_results)
    
    # Analyze URLs
    urls = email_data.get('urls', [])
    body_html = email_data.get('body_html', '')
    url_analysis = [analyze_url(url, body_html) for url in urls]
    
    # Analyze attachments
    attachments = analyze_attachments(email_data.get('attachments', []))
    
    # Calculate threat score
    score = 0
    
    # Feature-based scoring
    score += features['urgent_words_count'] * 5
    score += features['financial_terms_count'] * 8
    score += features['suspicious_phrases_count'] * 10
    
    if features['capital_ratio'] > 30:
        score += 15
    
    if features['exclamation_count'] > 3:
        score += 10
    
    # Authentication-based scoring
    if auth_results['spf_status'] == 'fail':
        score += 25
    if auth_results['dkim_status'] == 'fail':
        score += 25
    
    # Domain age scoring
    if features['domain_age_days'] is not None:
        if features['domain_age_days'] < 30:
            score += 30
        elif features['domain_age_days'] < 180:
            score += 15
    
    # URL-based scoring
    for url_info in url_analysis:
        if url_info['risk_level'] == 'malicious':
            score += 30
        elif url_info['risk_level'] == 'suspicious':
            score += 15
    
    # Attachment-based scoring
    for att in attachments:
        if att.get('is_dangerous'):
            score += 35
        elif att.get('is_suspicious'):
            score += 15
    
    # Determine label
    if score >= 60:
        label = 'phishing'
    elif score >= 40:
        label = 'scam'
    elif score >= 25:
        label = 'spam'
    else:
        label = 'safe'
    
    confidence = min(score + 20, 99)
    
    # Detect red flags
    red_flags = detect_red_flags(email_data, features, auth_results, url_analysis, attachments)
    
    return {
        'label': label,
        'confidence': confidence,
        'score': score,
        'red_flags': red_flags,
        'features': features,
        'url_analysis': url_analysis,
        'attachments': attachments
    }


def parse_eml_file(filepath):
    """Parse .eml file"""
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        subject = msg.get('subject', 'No Subject')
        sender = msg.get('from', 'Unknown')
        recipient = msg.get('to', 'Unknown')
        date = msg.get('date', 'Unknown')
        reply_to = msg.get('reply-to', '')
        
        body_text = ""
        body_html = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif content_type == 'text/html':
                    body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        urls = extract_urls(body_text) + extract_urls(body_html)
        
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'name': filename,
                            'type': part.get_content_type(),
                            'size': f"{len(part.get_payload(decode=True)) / 1024:.2f} KB"
                        })
        
        return {
            'subject': subject,
            'from': sender,
            'to': recipient,
            'date': date,
            'reply_to': reply_to,
            'body_text': body_text,
            'body_html': body_html,
            'urls': list(set(urls)),
            'attachments': attachments,
            'headers': dict(msg.items())
        }
    
    except Exception as e:
        raise Exception(f"Error parsing EML file: {str(e)}")


def parse_msg_file(filepath):
    """Parse .msg file"""
    try:
        msg = extract_msg.Message(filepath)
        
        subject = msg.subject or 'No Subject'
        sender = msg.sender or 'Unknown'
        recipient = msg.to or 'Unknown'
        date = msg.date or 'Unknown'
        body_text = msg.body or ''
        
        urls = extract_urls(body_text)
        
        attachments = []
        if hasattr(msg, 'attachments') and msg.attachments:
            for attachment in msg.attachments:
                attachments.append({
                    'name': attachment.longFilename or attachment.shortFilename,
                    'type': 'unknown',
                    'size': 'N/A'
                })
        
        msg.close()
        
        return {
            'subject': subject,
            'from': sender,
            'to': recipient,
            'date': str(date),
            'reply_to': '',
            'body_text': body_text,
            'body_html': '',
            'urls': list(set(urls)),
            'attachments': attachments,
            'headers': {}
        }
    
    except Exception as e:
        raise Exception(f"Error parsing MSG file: {str(e)}")



# --------- ROUTES ---------

@app.route("/")
def landing():
    return render_template("guest/index.html")

from werkzeug.security import generate_password_hash
from flask import request, redirect, render_template, flash

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        full_name = request.form["full_name"]
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        

        # Insert into DB (role uses default value)
        query = """
            INSERT INTO users (full_name, email, username, password)
            VALUES (%s, %s, %s, %s)
        """
        db.single_insert(query, (full_name, email, username, password))

        return redirect("/login")

    return render_template("guest/signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        query = """
            SELECT id, username, role
            FROM users
            WHERE username=%s AND password=%s
        """
        user = db.fetchone(query, (username, password))

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            # 🔁 Role-based redirection
            if user["role"] == "admin":
                return redirect("/admin/dashboard")
            else:
                return redirect("/user/dashboard")

        else:
            return render_template("guest/login.html", error="Invalid login!")

    return render_template("guest/login.html")


@app.route('/admin/dashboard')

def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect("/login")

    # Total scans
    total_scans = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM scan_history"
    )['cnt']

    # Total users
    total_users = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM users"
    )['cnt']

    # Total threats
    threat_count = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM scan_history WHERE label != 'safe'"
    )['cnt']

    # High-risk emails
    high_risk = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM scan_history WHERE confidence >= 85"
    )['cnt']

    # Threat distribution
    threat_distribution = db.fetchall("""
        SELECT label, COUNT(*) AS count
        FROM scan_history
        GROUP BY label
    """)

    # Scan trend
    scan_trend = db.fetchall("""
        SELECT DATE(created_at) AS day, COUNT(*) AS count
        FROM scan_history
        GROUP BY day
        ORDER BY day
    """)

    # Confidence distribution
    confidence_distribution = db.fetchall("""
        SELECT
            CASE
                WHEN confidence < 50 THEN 'Low'
                WHEN confidence BETWEEN 50 AND 75 THEN 'Medium'
                ELSE 'High'
            END AS level,
            COUNT(*) AS count
        FROM scan_history
        GROUP BY level
    """)

    # Scan type usage
    scan_type_distribution = db.fetchall("""
        SELECT scan_type, COUNT(*) AS count
        FROM scan_history
        GROUP BY scan_type
    """)

    # Recent high-risk scans
    recent_high_risk = db.fetchall("""
        SELECT subject, sender, label, confidence, created_at
        FROM scan_history
        WHERE confidence >= 85
        ORDER BY created_at DESC
        LIMIT 10
    """)

    return render_template(
        "admin/dashboard.html",
        total_scans=total_scans,
        total_users=total_users,
        threat_count=threat_count,
        high_risk=high_risk,
        threat_distribution=threat_distribution,
        scan_trend=scan_trend,
        confidence_distribution=confidence_distribution,
        scan_type_distribution=scan_type_distribution,
        recent_high_risk=recent_high_risk
    )


@app.route('/admin/threat-trends')

def admin_threat_trends():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect("/login")

    # Total threats (non-safe)
    total_threats = db.fetchone("""
        SELECT COUNT(*) AS cnt
        FROM scan_history
        WHERE label != 'safe'
    """)['cnt']

    # Threats over time (daily)
    threat_trend = db.fetchall("""
        SELECT 
            DATE(created_at) AS day,
            COUNT(*) AS count
        FROM scan_history
        WHERE label != 'safe'
        GROUP BY day
        ORDER BY day
    """)

    # Threats by label over time
    threat_by_label = db.fetchall("""
        SELECT 
            DATE(created_at) AS day,
            label,
            COUNT(*) AS count
        FROM scan_history
        WHERE label != 'safe'
        GROUP BY day, label
        ORDER BY day
    """)

    # Latest threat activity
    recent_threats = db.fetchall("""
        SELECT subject, sender, label, confidence, created_at
        FROM scan_history
        WHERE label != 'safe'
        ORDER BY created_at DESC
        LIMIT 15
    """)

    return render_template(
        "admin/threat_trends.html",
        total_threats=total_threats,
        threat_trend=threat_trend,
        threat_by_label=threat_by_label,
        recent_threats=recent_threats
    )
@app.route('/admin/model-insights')

def admin_model_insights():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect("/login")

    # Overall confidence statistics
    confidence_stats = db.fetchone("""
        SELECT 
            AVG(confidence) AS avg_confidence,
            MIN(confidence) AS min_confidence,
            MAX(confidence) AS max_confidence
        FROM scan_history
    """)

    # Confidence distribution
    confidence_distribution = db.fetchall("""
        SELECT
            CASE
                WHEN confidence < 50 THEN 'Low (<50%)'
                WHEN confidence BETWEEN 50 AND 75 THEN 'Medium (50–75%)'
                ELSE 'High (>75%)'
            END AS level,
            COUNT(*) AS count
        FROM scan_history
        GROUP BY level
    """)

    # Label vs average confidence
    label_confidence = db.fetchall("""
        SELECT 
            label,
            AVG(confidence) AS avg_confidence,
            COUNT(*) AS count
        FROM scan_history
        GROUP BY label
    """)

    # Rule triggers (from analysis_result JSON)
    rule_triggers = db.fetchall("""
        SELECT 
            JSON_UNQUOTE(JSON_EXTRACT(analysis_result, '$.rule')) AS rule_name,
            COUNT(*) AS count
        FROM scan_details
        WHERE JSON_EXTRACT(analysis_result, '$.rule') IS NOT NULL
        GROUP BY rule_name
        ORDER BY count DESC
        LIMIT 10
    """)

    # High confidence false positives (safe but high confidence)
    possible_false_positives = db.fetchall("""
        SELECT subject, sender, confidence, created_at
        FROM scan_history
        WHERE label = 'safe' AND confidence >= 85
        ORDER BY created_at DESC
        LIMIT 10
    """)

    return render_template(
        "admin/model_insights.html",
        confidence_stats=confidence_stats,
        confidence_distribution=confidence_distribution,
        label_confidence=label_confidence,
        rule_triggers=rule_triggers,
        possible_false_positives=possible_false_positives
    )

@app.route('/admin/users')

def admin_users():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect("/login")

    users = db.fetchall("""
        SELECT id, full_name, username, email, role, created_at
        FROM users
        WHERE role = 'user'
        ORDER BY created_at DESC
    """)

    return render_template(
        'admin/users.html',
        users=users
    )
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])

def delete_user(user_id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect("/login")

    # Prevent admin deleting themselves (important)
    if session.get('user_id') == user_id:
        flash("You cannot delete your own account", "error")
        return redirect('/admin/users')

    # Delete user
    db.execute(
        "DELETE FROM users WHERE id = %s",
        (user_id,)
    )

    flash("User deleted successfully", "success")
    return redirect('/admin/users')



@app.route('/user/dashboard')
def user_dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    total_scans = db.fetchone(
        "SELECT COUNT(*) as count FROM scan_history WHERE user_id = %s",
        (user_id,)
    )['count']
    
    threats = db.fetchone(
        "SELECT COUNT(*) as count FROM scan_history WHERE user_id = %s AND label IN ('phishing', 'spam', 'scam')",
        (user_id,)
    )['count']
    
    safe_count = db.fetchone(
        "SELECT COUNT(*) as count FROM scan_history WHERE user_id = %s AND label = 'safe'",
        (user_id,)
    )['count']
    
    recent_scans = db.fetchall(
        """SELECT subject, sender, label, confidence, DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i') as scan_date 
           FROM scan_history 
           WHERE user_id = %s 
           ORDER BY created_at DESC 
           LIMIT 10""",
        (user_id,)
    )
    
    return render_template('user/dashboard.html',
                         total_scans=total_scans,
                         threats=threats,
                         safe_count=safe_count,
                         recent_scans=recent_scans,
                         session=session)




@app.route('/user/scan/paste', methods=['POST'])
def scan_paste():
    """Handle pasted content (simplified analysis)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form.get('email_content', '').strip()
    
    if not content:
        flash('Please paste email content', 'error')
        return redirect(url_for('user_dashboard'))
    
    try:
        # Simple parsing for pasted content
        lines = content.strip().split('\n')
        
        subject = 'No Subject'
        sender = 'Unknown'
        recipient = 'Unknown'
        date = 'Unknown'
        body_lines = []
        
        for i, line in enumerate(lines):
            line_strip = line.strip()
            
            if line_strip.lower().startswith('subject:'):
                subject = line_strip.split(':', 1)[1].strip()
            elif line_strip.lower().startswith('from:'):
                sender = line_strip.split(':', 1)[1].strip()
            elif line_strip.lower().startswith('to:'):
                recipient = line_strip.split(':', 1)[1].strip()
            elif line_strip.lower().startswith('date:'):
                date = line_strip.split(':', 1)[1].strip()
            elif line_strip == '':
                body_lines = lines[i+1:]
                break
        
        if not body_lines:
            body_lines = lines
        
        body_text = '\n'.join(body_lines)
        urls = extract_urls(body_text)
        
        email_data = {
            'subject': subject,
            'from': sender,
            'to': recipient,
            'date': date,
            'reply_to': '',
            'body_text': body_text,
            'body_html': '',
            'urls': list(set(urls)),
            'attachments': [],
            'headers': {}
        }
        
        # Simplified analysis (no auth checks, no attachments)
        analysis_result = comprehensive_email_analysis(email_data)
        
        # Adjust confidence for pasted content (less reliable)
        analysis_result['confidence'] = max(analysis_result['confidence'] - 10, 50)
        
        db.execute(
            """INSERT INTO scan_history 
               (user_id, subject, sender, recipient, body, label, confidence, scan_type, created_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
            (
                session['user_id'],
                email_data['subject'],
                email_data['from'],
                email_data['to'],
                email_data['body_text'][:1000],
                analysis_result['label'],
                analysis_result['confidence'],
                'paste'
            )
        )
        
        return render_template('user/scan_result.html',
                             email_data=email_data,
                             result=analysis_result,
                             features=analysis_result['features'],
                             url_analysis=analysis_result['url_analysis'],
                             session=session)
    
    except Exception as e:
        flash(f'Error analyzing content: {str(e)}', 'error')
        return redirect(url_for('user_dashboard'))
    
#====================================================================
# 
# I'll include the essential ones here for completeness:

URGENT_WORDS = [
    'urgent', 'immediate', 'action required', 'verify', 'suspended', 'locked',
    'expires', 'limited time', 'act now', 'confirm', 'update required',
    'security alert', 'unusual activity', 'click here', 'verify account'
]

FINANCIAL_TERMS = [
    'bank', 'account', 'credit card', 'payment', 'invoice', 'wire transfer',
    'paypal', 'transaction', 'refund', 'money', 'cash', 'prize', 'winner',
    'bitcoin', 'cryptocurrency', 'investment'
]

# [Include all your existing analysis functions here]


def save_scan_details(scan_id, email_data, analysis_result, features, url_analysis):
    """Save detailed scan results to database"""
    try:
        db.execute(
            """INSERT INTO scan_details 
               (scan_id, email_data, analysis_result, features, url_analysis, created_at) 
               VALUES (%s, %s, %s, %s, %s, NOW())""",
            (
                scan_id,
                json.dumps(email_data),
                json.dumps(analysis_result),
                json.dumps(features),
                json.dumps(url_analysis)
            )
        )
    except Exception as e:
        print(f"Error saving scan details: {e}")


def get_scan_details(scan_id):
    """Retrieve detailed scan results from database"""
    try:
        details = db.fetchone(
            "SELECT * FROM scan_details WHERE scan_id = %s",
            (scan_id,)
        )
        
        if details:
            return {
                'email_data': json.loads(details['email_data']),
                'analysis_result': json.loads(details['analysis_result']),
                'features': json.loads(details['features']),
                'url_analysis': json.loads(details['url_analysis'])
            }
    except Exception as e:
        print(f"Error retrieving scan details: {e}")
    
    return None


def generate_pdf_report(scan_data, email_data, result, features, url_analysis):
    """Generate PDF report of scan results"""
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#00eaff'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#00eaff'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    # Title
    story.append(Paragraph("DeepSecure Email Analysis Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Threat Banner
    threat_color = {
        'safe': colors.HexColor('#4dff88'),
        'phishing': colors.HexColor('#ff4d4d'),
        'spam': colors.HexColor('#ffb84d'),
        'scam': colors.HexColor('#ff6b35')
    }.get(result['label'], colors.grey)
    
    threat_data = [
        ['THREAT LEVEL', result['label'].upper()],
        ['CONFIDENCE', f"{result['confidence']}%"],
        ['SCAN DATE', scan_data['scan_date']]
    ]
    
    threat_table = Table(threat_data, colWidths=[2*inch, 4*inch])
    threat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f233c')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#00eaff')),
        ('TEXTCOLOR', (1, 0), (1, 0), threat_color),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#00c8ff')),
    ]))
    story.append(threat_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Email Information
    story.append(Paragraph("📧 Email Information", heading_style))
    email_info_data = [
        ['Subject:', email_data['subject'][:70]],
        ['From:', email_data['from']],
        ['To:', email_data['to']],
        ['Date:', email_data['date']],
    ]
    
    email_table = Table(email_info_data, colWidths=[1.5*inch, 5*inch])
    email_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f233c')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#b7e9ff')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00c8ff')),
    ]))
    story.append(email_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Red Flags
    if result.get('red_flags') and len(result['red_flags']) > 0:
        story.append(Paragraph("🚩 Red Flags Detected", heading_style))
        for flag in result['red_flags']:
            story.append(Paragraph(f"<b>{flag['type']}:</b> {flag['message']}", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        story.append(Spacer(1, 0.2*inch))
    
    # Email Authentication
    story.append(Paragraph("🔐 Email Authentication", heading_style))
    auth_data = [
        ['SPF Status:', features.get('spf_status', 'unknown').upper()],
        ['DKIM Status:', features.get('dkim_status', 'unknown').upper()],
        ['DMARC Status:', features.get('dmarc_status', 'unknown').upper()],
        ['Domain Age:', f"{features.get('domain_age_days', 'Unknown')} days" if features.get('domain_age_days') else 'Unknown'],
    ]
    
    auth_table = Table(auth_data, colWidths=[2*inch, 4*inch])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f233c')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#b7e9ff')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00c8ff')),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Feature Analysis
    story.append(Paragraph("🔬 Feature Analysis", heading_style))
    feature_data = [
        ['Text Length:', f"{features.get('text_length', 0)} characters"],
        ['Urgent Words:', str(features.get('urgent_words_count', 0))],
        ['Financial Terms:', str(features.get('financial_terms_count', 0))],
        ['Suspicious Phrases:', str(features.get('suspicious_phrases_count', 0))],
        ['Capital Ratio:', f"{features.get('capital_ratio', 0)}%"],
        ['Exclamation Marks:', str(features.get('exclamation_count', 0))],
    ]
    
    feature_table = Table(feature_data, colWidths=[2*inch, 4*inch])
    feature_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f233c')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#b7e9ff')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00c8ff')),
    ]))
    story.append(feature_table)
    story.append(Spacer(1, 0.2*inch))
    
    # URL Analysis
    if url_analysis and len(url_analysis) > 0:
        story.append(Paragraph(f"🔗 URL Analysis ({len(url_analysis)} URLs)", heading_style))
        for i, url_info in enumerate(url_analysis[:5]):  # Limit to 5 URLs
            url_data = [
                ['URL:', url_info['url'][:60]],
                ['Domain:', url_info['domain']],
                ['HTTPS:', 'Yes' if url_info['is_https'] else 'No'],
                ['Risk Level:', url_info['risk_level'].upper()],
            ]
            
            url_table = Table(url_data, colWidths=[1.5*inch, 5*inch])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0a1929')),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#b7e9ff')),
                ('TEXTCOLOR', (1, 0), (1, -1), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00c8ff')),
            ]))
            story.append(url_table)
            story.append(Spacer(1, 0.1*inch))
    
    # Attachments
    if email_data.get('attachments') and len(email_data['attachments']) > 0:
        story.append(Paragraph(f"📎 Attachments ({len(email_data['attachments'])})", heading_style))
        for att in email_data['attachments']:
            att_text = f"• {att['name']} ({att.get('type', 'unknown')})"
            if att.get('is_dangerous'):
                att_text += " - ⚠️ DANGEROUS"
            elif att.get('is_suspicious'):
                att_text += " - ⚠️ SUSPICIOUS"
            story.append(Paragraph(att_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
    
    # Email Body Preview
    story.append(Paragraph("📝 Email Body Preview", heading_style))
    body_preview = email_data['body_text'][:500] if email_data.get('body_text') else 'No body text'
    # story.append(Paragraph(body_preview.replace('\n', '<br/>'), styles['Normal']))
    story.append(
    Paragraph(escape(body_preview).replace('\n', '<br/>'), styles['Normal']))
    
    # Footer
    story.append(Spacer(1, 0.3*inch))
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_CENTER
    )
    story.append(Paragraph("Generated by DeepSecure Mail Analyzer", footer_style))
    story.append(Paragraph(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer


@app.route('/user/history')
def scan_history():
    """Display scan history with filters and pagination"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Get filter and search parameters
    filter_type = request.args.get('filter', 'all')
    search_query = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    per_page = 15
    
    # Build query
    base_query = "SELECT * FROM scan_history WHERE user_id = %s"
    count_query = "SELECT COUNT(*) as count FROM scan_history WHERE user_id = %s"
    params = [user_id]
    
    # Apply filters
    if filter_type == 'safe':
        base_query += " AND label = 'safe'"
        count_query += " AND label = 'safe'"
    elif filter_type == 'threats':
        base_query += " AND label IN ('phishing', 'spam', 'scam')"
        count_query += " AND label IN ('phishing', 'spam', 'scam')"
    
    # Apply search
    if search_query:
        base_query += " AND (subject LIKE %s OR sender LIKE %s)"
        count_query += " AND (subject LIKE %s OR sender LIKE %s)"
        search_param = f"%{search_query}%"
        params.extend([search_param, search_param])
    
    # Get total count
    total_count = db.fetchone(count_query, tuple(params))['count']
    total_pages = (total_count + per_page - 1) // per_page
    
    # Get paginated results
    offset = (page - 1) * per_page
    base_query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    params.extend([per_page, offset])
    
    scans = db.fetchall(base_query, tuple(params))
    
    # Format dates
    for scan in scans:
        scan['scan_date'] = scan['created_at'].strftime('%Y-%m-%d %H:%M')
    
    # Get counts for filter buttons
    counts = {
        'total': db.fetchone(
            "SELECT COUNT(*) as count FROM scan_history WHERE user_id = %s",
            (user_id,)
        )['count'],
        'safe': db.fetchone(
            "SELECT COUNT(*) as count FROM scan_history WHERE user_id = %s AND label = 'safe'",
            (user_id,)
        )['count'],
        'threats': db.fetchone(
            "SELECT COUNT(*) as count FROM scan_history WHERE user_id = %s AND label IN ('phishing', 'spam', 'scam')",
            (user_id,)
        )['count']
    }
    
    return render_template('user/scan_history.html',
                         scans=scans,
                         counts=counts,
                         filter_type=filter_type,
                         search_query=search_query,
                         page=page,
                         total_pages=total_pages,
                         session=session)


@app.route('/user/history/view/<int:scan_id>')
def view_scan_result(scan_id):
    """View detailed scan result"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Verify ownership
    scan = db.fetchone(
        "SELECT * FROM scan_history WHERE id = %s AND user_id = %s",
        (scan_id, session['user_id'])
    )
   
    
    if not scan:
        flash('Scan not found', 'error')
        return redirect(url_for('scan_history'))
    
    # Get detailed results
    details = get_scan_details(scan_id)
    
    if not details:
        flash('Detailed scan results not available', 'error')
        return redirect(url_for('scan_history'))
    
    return render_template('user/scan_result.html',
                         email_data=details['email_data'],
                         result=details['analysis_result'],
                         features=details['features'],
                         url_analysis=details['url_analysis'],
                         session=session)


@app.route('/user/history/download/<int:scan_id>')
def download_scan_pdf(scan_id):
    """Download scan result as PDF"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Verify ownership
    scan = db.fetchone(
        "SELECT * FROM scan_history WHERE id = %s AND user_id = %s",
        (scan_id, session['user_id'])
    )
    
    if not scan:
        flash('Scan not found', 'error')
        return redirect(url_for('scan_history'))
    
    # Get detailed results
    details = get_scan_details(scan_id)
    
    if not details:
        flash('Detailed scan results not available', 'error')
        return redirect(url_for('scan_history'))
    
    # Format scan data
    scan['scan_date'] = scan['created_at'].strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate PDF
    pdf_buffer = generate_pdf_report(
        scan,
        details['email_data'],
        details['analysis_result'],
        details['features'],
        details['url_analysis']
    )
    
    # Create filename
    filename = f"DeepSecure_Scan_{scan_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )


@app.route('/user/history/delete/<int:scan_id>')
def delete_scan(scan_id):
    """Delete a scan from history"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Verify ownership
    scan = db.fetchone(
        "SELECT * FROM scan_history WHERE id = %s AND user_id = %s",
        (scan_id, session['user_id'])
    )
    
    if not scan:
        flash('Scan not found', 'error')
        return redirect(url_for('scan_history'))
    
    # Delete scan (cascade will delete scan_details)
    db.execute("DELETE FROM scan_history WHERE id = %s", (scan_id,))
    
    flash('Scan deleted successfully', 'success')
    return redirect(url_for('scan_history'))



@app.route('/user/scan/upload', methods=['POST'])
def scan_upload():
    """Handle file upload - MODIFIED to save details"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'email_file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('user_dashboard'))
    
    file = request.files['email_file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('user_dashboard'))
    
    if not allowed_file(file.filename):
        flash('Invalid file type. Please upload .eml or .msg files only.', 'error')
        return redirect(url_for('user_dashboard'))
    
    filepath = None
    
    try:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        file_ext = filename.rsplit('.', 1)[1].lower()
        
        if file_ext == 'eml':
            email_data = parse_eml_file(filepath)
        elif file_ext == 'msg':
            email_data = parse_msg_file(filepath)
        else:
            raise Exception('Unsupported file type')
        
        # Comprehensive analysis
        analysis_result = comprehensive_email_analysis(email_data)
        
        # Save to database and get scan_id
        scan_id = db.executeAndReturnId(
            """INSERT INTO scan_history 
               (user_id, subject, sender, recipient, body, label, confidence, scan_type, created_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
            (
                session['user_id'],
                email_data['subject'],
                email_data['from'],
                email_data['to'],
                email_data['body_text'][:1000],
                analysis_result['label'],
                analysis_result['confidence'],
                'upload'
            )
        )
        
        # Save detailed results
        save_scan_details(
            scan_id,
            email_data,
            analysis_result,
            analysis_result['features'],
            analysis_result['url_analysis']
        )
        
        # Clean up
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        
        # Show detailed results
        return render_template('user/scan_result.html',
                             email_data=email_data,
                             result=analysis_result,
                             features=analysis_result['features'],
                             url_analysis=analysis_result['url_analysis'],
                             session=session)
    
    except Exception as e:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        flash(f'Error processing file: {str(e)}', 'error')
        return redirect(url_for('user_dashboard'))
    

@app.route('/user/tips')
def user_tips():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('user/tips.html', session=session)

#============ Logout Route ============

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# -------- RUN --------
if __name__ == "__main__":
    app.run(debug=True)
