import re
from urllib.parse import urlparse

def extract_features(url):

    features = {}

    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['has_https'] = 1 if "https" in url else 0

    domain = urlparse(url).netloc
    features['domain_length'] = len(domain)

    return list(features.values())
