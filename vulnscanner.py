#!/usr/local/bin/python3

#!/usr/local/bin/python3

import argparse
import os
import re
import chardet

def is_text_file(filepath):
    """Determine if a file is text or binary."""
    with open(filepath, 'rb') as f:
        result = chardet.detect(f.read(1024))
        return result['encoding'] is not None

def scan_file(filename, search_patterns):
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for line_no, line in enumerate(lines, 1):
        for category, patterns in search_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    discovered_item = match.group(1) if match.groups() else match.group(0)  # Get the captured item if there's a capture group
                    
                    # Clean up for displaying
                    clean_item = discovered_item.replace(r'\b', '').replace(r'\(', '').replace(r'\*', '*').replace(r'\)', '').replace(r'\/', '/').replace(r'(','')
                    
                    # Provide specific prints for each category
                    if category == "passwords":
                        print(f'Found passwords: password = {clean_item} in {filename} at line {line_no}')
                    elif category == "weak_ciphers":
                        print(f'Found weak cipher: {clean_item} in {filename} at line {line_no}')
                    elif category == "vulnerable_sql":
                        print(f'Found SQL vulnerability: {clean_item} in {filename} at line {line_no}')
                    elif category == "plain_http_requests":
                        print(f'Found plain HTTP request: {clean_item} in {filename} at line {line_no}')
                    elif category == "no_input_validation":
                        print(f'Found input validation issue: {clean_item} in {filename} at line {line_no}')
                    elif category == "hardcoded_keys":
                        print(f'Found hardcoded key: {clean_item} in {filename} at line {line_no}')
                    elif category == "unsafe_file_operations":
                        print(f'Found unsafe file operation: {clean_item} in {filename} at line {line_no}')
                    elif category == "exposed_secrets":
                        print(f'Found exposed secret: {clean_item} in {filename} at line {line_no}')
                    elif category == "debug_enabled":
                        print(f'Found debug enabled: {clean_item} in {filename} at line {line_no}')
                    elif category == "unencrypted_transmissions":
                        print(f'Found unencrypted transmission pattern: {clean_item} in {filename} at line {line_no}')
                    elif category == "ssl_verification_disabled":
                        print(f'Found SSL verification disabled: {clean_item} in {filename} at line {line_no}')
                    else:
                        print(f'Found {category}: {clean_item} in {filename} at line {line_no}')


def main():
    try:
        parser = argparse.ArgumentParser(description="Scan a directory for vulnerabilities")
        parser.add_argument('directory', help="The directory to scan")
        parser.add_argument('-r', '--recursive', action="store_true", help="Scan recursively")
        parser.add_argument('--all', action="store_true", help="Search for all vulnerabilities")

        unsafe_file_operations_patterns = [
            r'open\s*\(',  # Python file open
            r'os\.remove', # Python os.remove
            r'os\.rmdir',  # Python os.rmdir
            r'\b(del|erase)\b',  # Windows batch file delete
            r'\b(rmdir|rd)\b',  # Windows batch file remove directory
            r'Remove-Item',  # PowerShell delete cmdlet
            r'Out-File',    # PowerShell write to file
        ]

        potential_memory_corruption_patterns = [
            # Current patterns
            r'\bunsafe\b',
            r'\bfixed\b',
            r'\bMarshal\.\b',
        
            # Buffer Overflows
            r'\b(strcpy|sprintf|gets|strcat)\s*\(',
            r'char\s+\w+\s*\[\s*\d+\s*\]',
 
            # Heap Overflows
            r'\b(malloc|free|new|delete)\b',
        
            # Format String Vulnerabilities
            r'printf\([^"]+',
        
            # Use-After-Free
            r'\b(free|delete)\s+\w+',
        
            # Memory Leaks
            r'\b(malloc|new)\b',
        
            # Dangling Pointers
            r'\bfree\((?P<varname>\w+)\)\s*;[^}]*\(?P=varname\)',
 
            # C# specific
            r'\bDllImport\b',
        
            # Pointer Arithmetics
            r'\w+\s*\*\s*\w+\s*(\+|\-|\*|\&)'
        ]

        # Defining checks
        checks = {
            "passwords": [r'\bpassword\s*=\s*["\'](.*?)["\']', r'\bpassword\s*\(\s*["\'](.*?)["\']\s*\)', r'\bsetPassword\s*\(\s*["\'](.*?)["\']\s*\)', r'(?i)\bpassword\b'],
            "weak_ciphers": [r'\b(MD5|SHA1|DES|RC4)\b'],
            "vulnerable_sql": [r'SELECT \* FROM', r'exec\s*\('],
            "plain_http_requests": [r'http://'],
            "no_input_validation": [r'\.Parse\(', r'\.Convert\.To', r'\bSystem\.Web\.Http\.HttpMethod\.Get\b'],
            "hardcoded_keys": [r'\b(AES|DES|RSA|API_KEY|SECRET)\s*=\s*["\']\w+["\']'],
            "unsafe_file_operations": [pattern for pattern in unsafe_file_operations_patterns],
            "exposed_secrets": [r'(?i)\b(SECRET|API_KEY|PASSWORD)\s*=\s*["\']?[\w\-_!@#$%^&*()+=\[\]{}|;:,.<>?~]+["\']?'],
            "debug_enabled": [r'\bDEBUG\s*=\s*True\b'],
            "ssl_verification_disabled": [r'\bverify\s*=\s*False\b'],
            "lack_of_input_length_check": [r'\.Length[^<>=]*[<>][^=]*\d+'],
            "potential_memory_corruption": potential_memory_corruption_patterns,
            "unsafe_pointer_usage": [r'\bbyte\*', r'\bint\*', r'\bchar\*'],
            "unencrypted_transmissions": [r'\bEncrypt\s*=\s*[\'"]?\s*False\s*[\'"]?\b']
        }

        # Adding checks to the argument parser
        for check, _ in checks.items():
            flag = check.replace("_", "-")
            help_message = f"Search for {check.replace('_', ' ')} vulnerabilities"
            parser.add_argument(f'--{flag}', action="store_true", help=help_message)

        parser.add_argument('-c', '--custom-patterns', nargs='+', help="Add custom regex patterns to search for")

        args = parser.parse_args()

        # Determine patterns to check based on user input
        patterns_to_check = {}

        for check, patterns in checks.items():
            if getattr(args, check) or args.all:
                patterns_to_check[check] = patterns

        if args.custom_patterns:
            patterns_to_check["custom"] = args.custom_patterns

        for root, _, files in os.walk(args.directory):
            for file in files:
                filepath = os.path.join(root, file)
                if is_text_file(filepath):
                    scan_file(filepath, patterns_to_check)
            if not args.recursive:
                break
    except KeyboardInterrupt as e:
        print("\nUser pressed CTRL-C\n")
        exit()

if __name__ == "__main__":
    main()

