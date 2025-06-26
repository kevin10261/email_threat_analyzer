# This module contains functions to calculate risk scores based on email authentication results.
def calculate_risk(auth_results, link_flags, mismatch):
    score = 0
    if auth_results['SPF'] == 'fail': score += 3
    if auth_results['DKIM'] == 'fail': score += 2
    if auth_results['DMARC'] == 'fail': score += 2
    if mismatch: score += 2
    if any(link_flags.values()): score += 3
    return min(score, 10)  # Cap score at 10