from utils.header_parser import parse_headers, check_authentication, check_mismatch
from utils.link_scanner import extract_links, scan_links
from utils.risk_scoring import calculate_risk
import sys
from email import message_from_binary_file
from typing import Optional

# This script analyzes an email file (.eml) for potential threats by checking headers, authentication results, and links.
def extract_email_body(eml_path: str) -> Optional[str]:
    try:
        with open(eml_path, 'rb') as f:
            msg = message_from_binary_file(f)

        if msg.is_multipart():
            for part in msg.walk():
                # Look for both text/plain and text/html content
                if part.get_content_type() in ['text/plain', 'text/html']:
                    # Skip attachments
                    if part.get_content_disposition() == 'attachment':
                        continue
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode(errors='ignore')
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode(errors='ignore')
    except Exception as e:
        print(f"[!] Error reading email body: {e}")
    return None

# This is the main function that orchestrates the email analysis.
# It reads the email file, parses headers, checks authentication results, extracts links, scans them,
# and calculates a risk score based on the findings.
# It prints a report summarizing the analysis results.
def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <email_file.eml>")
        return

    eml_path = sys.argv[1]
    headers = parse_headers(eml_path)
    auth_results = check_authentication(headers)
    mismatch = check_mismatch(headers)
    email_body = extract_email_body(eml_path)

    if not email_body:
        print("[!] Failed to extract email body.")
        return

    links = extract_links(email_body)
    scanned_links = scan_links(links)
    risk_score = calculate_risk(auth_results, scanned_links, mismatch)

    # Display created using ChatGPT
    print("\n=== Email Threat Analysis Report ===")
    print(f"From: {headers.get('From', 'N/A')}")
    print(f"Reply-To: {headers.get('Reply-To', 'N/A')}")
    print(f"SPF: {auth_results['SPF']}")
    print(f"DKIM: {auth_results['DKIM']}")
    print(f"DMARC: {auth_results['DMARC']}")
    print(f"Sender mismatch: {'Yes' if mismatch else 'No'}")
    if scanned_links:
        print("\nSuspicious Links:")
        for link, flagged in scanned_links.items():
            print(f" - {link} --> {'MALICIOUS' if flagged else 'Safe'}")
    print(f"\nRisk Score: {risk_score}/10")
    if risk_score >= 7:
        print("❌ Result: DANGEROUS")
    elif risk_score >= 4:
        print("⚠️ Result: SUSPICIOUS")
    else:
        print("✅ Result: SAFE")

if __name__ == "__main__":
    main()
