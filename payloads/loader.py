"""
Payload Loader - Load payloads from hierarchical directory structure.
"""
from pathlib import Path
from typing import Dict, List, Optional

PAYLOADS_DIR = Path(__file__).parent

CATEGORIES = {
    'injection': ['sqli', 'nosql', 'ldap', 'command'],
    'xss': ['reflected', 'dom', 'polyglot'],
    'traversal': ['lfi', 'rfi'],
    'ssrf': ['basic', 'cloud', 'protocols'],
    'auth': ['bypass', 'jwt', 'mass_assignment', 'hidden_params'],
    'misc': ['ssti', 'xxe', 'prototype', 'headers', 'redirect'],
}


def load_payloads(category: str, subcategory: Optional[str] = None) -> List[str]:
    """
    Load payloads from file.

    Args:
        category: Main category (injection, xss, traversal, ssrf, auth, misc)
        subcategory: Specific type within category (e.g., sqli, reflected)

    Returns:
        List of payload strings
    """
    payloads = []

    if subcategory:
        file_path = PAYLOADS_DIR / category / f"{subcategory}.txt"
        if file_path.exists():
            payloads = _load_file(file_path)
    else:
        # Load all subcategories
        cat_dir = PAYLOADS_DIR / category
        if cat_dir.exists():
            for file_path in cat_dir.glob("*.txt"):
                payloads.extend(_load_file(file_path))

    return payloads


def _load_file(path: Path) -> List[str]:
    """Load payloads from a single file, filtering comments."""
    payloads = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                payloads.append(line)
    return payloads


def load_all() -> Dict[str, Dict[str, List[str]]]:
    """Load all payloads organized by category."""
    all_payloads = {}

    for category, subcategories in CATEGORIES.items():
        all_payloads[category] = {}
        for sub in subcategories:
            payloads = load_payloads(category, sub)
            if payloads:
                all_payloads[category][sub] = payloads

    return all_payloads


def get_category_count() -> Dict[str, int]:
    """Get payload count per category."""
    counts = {}
    for category in CATEGORIES:
        payloads = load_payloads(category)
        counts[category] = len(payloads)
    return counts


def search_payloads(keyword: str) -> List[Dict]:
    """Search payloads containing keyword."""
    results = []

    for category, subcategories in CATEGORIES.items():
        for sub in subcategories:
            payloads = load_payloads(category, sub)
            for payload in payloads:
                if keyword.lower() in payload.lower():
                    results.append({
                        'category': category,
                        'subcategory': sub,
                        'payload': payload
                    })

    return results


# Quick access functions
def sqli() -> List[str]:
    return load_payloads('injection', 'sqli')

def xss() -> List[str]:
    return load_payloads('xss')

def lfi() -> List[str]:
    return load_payloads('traversal', 'lfi')

def ssrf() -> List[str]:
    return load_payloads('ssrf')

def ssti() -> List[str]:
    return load_payloads('misc', 'ssti')

def mass_assignment() -> List[str]:
    return load_payloads('auth', 'mass_assignment')
