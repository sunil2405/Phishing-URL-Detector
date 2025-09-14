# src/features.py
import re
from urllib.parse import urlparse
import math

IP_PATTERN = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')

def has_ip(netloc):
    # detect raw IPv4 host
    return bool(IP_PATTERN.match(netloc))

def count_digits(s):
    return sum(ch.isdigit() for ch in s)

def count_subdomains(hostname):
    if not hostname:
        return 0
    return len(hostname.split('.')) - 2 if '.' in hostname else 0

def has_at_symbol(url):
    return '@' in url

def count_hyphens(s):
    return s.count('-')

def suspicious_tld(netloc):
    # heuristic: very long last label? Or uncommon (can't check list offline).
    parts = netloc.split('.')
    if len(parts) < 2:
        return 1
    last = parts[-1]
    return 1 if len(last) > 4 else 0

def path_length(parsed):
    return len(parsed.path or '')

def query_length(parsed):
    return len(parsed.query or '')

def token_entropy(s):
    # rough entropy estimate on the hostname
    if not s:
        return 0.0
    probs = {}
    for ch in s:
        probs[ch] = probs.get(ch, 0) + 1
    total = len(s)
    ent = 0.0
    for v in probs.values():
        p = v / total
        ent -= p * math.log2(p)
    return ent

def extract_features(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        host = netloc[4:]
    else:
        host = netloc
    features = {
        "url_length": len(url),
        "host_length": len(host),
        "has_ip": int(has_ip(host)),
        "count_digits": count_digits(url),
        "count_subdomains": count_subdomains(host),
        "has_at": int(has_at_symbol(url)),
        "count_hyphens": count_hyphens(host),
        "suspicious_tld": suspicious_tld(host),
        "path_len": path_length(parsed),
        "query_len": query_length(parsed),
        "hostname_entropy": token_entropy(host),
    }
    return features
