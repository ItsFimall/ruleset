import requests
import json
import sys
import ipaddress
from pathlib import Path

# --- Configuration ---
# This configuration now creates a separate file for each of the original "DIRECT" sources.
RULE_CONFIG = {
    # Each of the following is now its own group, creating a separate file
    "PRIVATE": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/private.txt"
    ],
    "CNCIDR": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt"
    ],
    "DIRECT": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/direct.txt"
    ],
    
    # The rest of the configuration remains the same
    "REJECT": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/reject.txt"
    ],
    "PROXY": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/proxy.txt"
    ],
    "GOOGLE": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/google.txt"
    ],
    "APPLE": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/apple.txt"
    ]
}

# Directory to save the intermediate JSON files and final SRS files
OUTPUT_DIR = Path("dist")

def is_ip_cidr(line):
    """Check if a line is a valid IP address or CIDR range."""
    try:
        ipaddress.ip_network(line, strict=False)
        return True
    except ValueError:
        return False

def parse_and_convert(group_name, urls):
    """
    Downloads rules from a list of URLs, parses them, and returns a list
    of sing-box rule dictionaries.
    """
    print(f"[*] Processing group: {group_name}")
    
    singbox_rules = []
    for url in urls:
        print(f"  - Downloading from {url}")
        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"  [!] Error: Failed to download {url}. {e}")
            continue

        lines = response.text.splitlines()
        for line in lines:
            line = line.strip()
            
            # Ignore comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Heuristic to detect rule type
            if ',' in line: # Likely Surge format (e.g., DOMAIN,google.com)
                try:
                    rule_type, value = line.split(',', 1)
                    rule_type_upper = rule_type.strip().upper()
                    value_stripped = value.strip()
                    if rule_type_upper == 'DOMAIN-SUFFIX':
                        singbox_rules.append({"domain_suffix": value_stripped})
                    elif rule_type_upper == 'DOMAIN':
                        singbox_rules.append({"domain": value_stripped})
                    elif rule_type_upper == 'DOMAIN-KEYWORD':
                        singbox_rules.append({"domain_keyword": value_stripped})
                    elif rule_type_upper == 'IP-CIDR':
                        singbox_rules.append({"ip_cidr": value_stripped})
                    else:
                        print(f"  [!] Skipping unsupported Surge rule: {line}")
                except ValueError:
                    print(f"  [!] Skipping malformed Surge rule: {line}")
            elif is_ip_cidr(line): # Likely a plain IP/CIDR list
                singbox_rules.append({"ip_cidr": line})
            else: # Assume it's a domain/suffix rule if it's not a comment or IP
                 singbox_rules.append({"domain_suffix": line})

    print(f"[+] Group '{group_name}' processed with {len(singbox_rules)} rules.")
    return singbox_rules

def main():
    """Main function to run the conversion process."""
    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir()

    for group_name, urls in RULE_CONFIG.items():
        rules = parse_and_convert(group_name, urls)
        
        if not rules:
            print(f"[!] No rules found for group '{group_name}', skipping file creation.")
            continue
            
        final_json = {
            "version": 1,
            "rules": rules
        }
        
        output_path = OUTPUT_DIR / f"{group_name}.json"
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(final_json, f, indent=2)
            print(f"  -> Successfully created JSON: {output_path}")
        except IOError as e:
            print(f"  [!] Error writing file {output_path}. {e}")

if __name__ == "__main__":
    main()
