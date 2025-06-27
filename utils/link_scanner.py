import re
from typing import List, Dict
import requests
import time
from urllib.parse import urlparse

API_KEY = "INSERT_API_KEY"
HEADERS = {'API-Key': API_KEY, 'Content-Type': 'application/json'}

# This function extracts links from the email body, filters out image URLs, and returns a list of cleaned URLs.
# It uses regular expressions to find URLs and applies various cleaning steps to ensure the URLs are valid
# and not related to images or common image-related keywords.
# The function returns a list of unique URLs that are suitable for further scanning.
def extract_links(email_body: str) -> List[str]:
    
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*'
    
    
    urls = re.findall(url_pattern, email_body)
    
    
    cleaned_urls = []
    for url in urls:
        
        url = url.rstrip('.,;!?)')
         
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico')
        if any(url.lower().endswith(ext) for ext in image_extensions):
            continue
        
        image_keywords = ['logo', 'banner', 'header', 'icon', 'image', 'img']
        if any(keyword in url.lower() for keyword in image_keywords):
            continue
        
        cleaned_urls.append(url)
    
    return list(set(cleaned_urls))  # Remove duplicates

# This function scans a list of URLs using the urlscan.io API.
# It submits each URL for scanning and checks the results to determine if the URL is malicious.
# The function respects API rate limits and handles errors gracefully.
# It returns a dictionary where the keys are URLs and the values are booleans indicating whether the URL is malicious.
# The function checks various threat indicators such as overall score, verdicts from urlscan, and individual engine flags.
# If the scan fails or the URL is unreachable, it defaults to marking the URL as safe unless it is unreachable.
def scan_links(links: List[str]) -> Dict[str, bool]:
    result = {}
    for link in links:
        try:
            scan_data = {
                "url": link,
                "visibility": "public"
            }
            res = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers=HEADERS,
                json=scan_data
            )
            time.sleep(2) 
            
            if res.status_code == 200:
                scan_result = res.json()
                # Wait for scan to complete
                time.sleep(15)
                
                result_url = scan_result.get('api')
                if result_url:
                    result_response = requests.get(result_url, headers=HEADERS)
                    if result_response.status_code == 200:
                        scan_data = result_response.json()
                        verdicts = scan_data.get('verdicts', {})
                        
                        overall = verdicts.get('overall', {})
                        urlscan = verdicts.get('urlscan', {})
                        engines = verdicts.get('engines', {})
                        
                        is_malicious = (
                            overall.get('malicious', False) or
                            urlscan.get('malicious', False) or
                            overall.get('score', 0) > 50 or
                            any(engine.get('malicious', False) for engine in engines.values() if isinstance(engine, dict))
                        )
                        
                        result[link] = is_malicious
                    else:
                        try:
                            test_response = requests.head(link, timeout=10, allow_redirects=True)
                            result[link] = test_response.status_code >= 400
                        except requests.exceptions.RequestException:
                            result[link] = True 
                else:
                    result[link] = False  
            else:
                try:
                    test_response = requests.head(link, timeout=10, allow_redirects=True)
                    result[link] = test_response.status_code >= 400
                except requests.exceptions.RequestException:
                    result[link] = True 
                    
        except Exception as e:
            print(f"Error scanning {link}: {str(e)}")
            result[link] = False 
            
    return result
