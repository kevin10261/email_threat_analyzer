from email import message_from_file


# In this function, I will open the .eml file in text mode.
#Then using the email library we will parse the content using message_from_file.
#Finally, I will return the headers as a dictionary since its easier to work with.
def parse_headers(eml_path):
    with open(eml_path, 'r') as f:
        msg = message_from_file(f)
    return dict(msg.items())

#This function checks the Authentication-Results header for SPF, DKIM, and DMARC results.
# SPF,DKIM and DMARC are three email authentication methods that help to prevent email spoofing.
# DKIM and SPF can be compared to a business license, mean while DMARC tells mail servers what to do when DKIM or SPF fail, which is usually how a email is sent to 
# the spam folder.
def check_authentication(headers):
    result = {"SPF": "unknown", "DKIM": "unknown", "DMARC": "unknown"}
    auth = headers.get('Authentication-Results', '').lower()
    if "spf=fail" in auth: result ["SPF"] = "fail"
    elif "spf=pass" in auth: result["SPF"] = "pass"
    if "dkim=fail" in auth: result["DKIM"] = "fail"
    elif "dkim=pass" in auth: result["DKIM"] = "pass"
    if "dmarc=fail" in auth: result["DMARC"] = "fail"
    elif "dmarc=pass" in auth: result["DMARC"] = "pass"
    return result

# This function checks if the Return-Path header matches the From header.
# A mismatch can indicate that the email is spoofed or forged.
# The Return-Path header is the address that bounces are sent to, while the From header is the address that appears in the email client.
# If the Return-Path does not match the From address, it may indicate that the email is not from the claimed sender.
# The function returns True if there is a mismatch, otherwise it returns False.
def check_mismatch(headers):
    return_path = headers.get('Return-Path', '').strip('<>')
    from_addr = headers.get('From', '')
    return return_path not in from_addr
