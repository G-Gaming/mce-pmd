#!/usr/bin/env python3
"""
Scan all .c and .h files for functions lacking Doxygen documentation
"""

import re
from pathlib import Path
from collections import defaultdict

def scan_files():
    """Scan all C/H files for undocumented functions"""
    src_dir = Path("drivers/net/mce")
    
    # Patterns
    doxy_pattern = r'/\*\*\s*\n\s*\*\s*@brief'
    func_pattern = r'^\s*(static\s+)?(inline\s+)?(const\s+)?([a-zA-Z_][a-zA-Z0-9_*\s]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*(?:;|{|\n)'
    
    results = defaultdict(list)
    
    # Get all .c and .h files
    files = sorted(list(src_dir.glob('**/*.c')) + list(src_dir.glob('**/*.h')))
    files = [f for f in files if 'base' not in str(f)]
    
    for filepath in files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            continue
        
        rel_path = filepath.relative_to(src_dir.parent)
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Look for function-like patterns (not inside comments, strings, etc)
            if re.match(r'^[a-zA-Z_].*\s+\w+\s*\([^)]*\)\s*(?:;|{|\n|$)', line):
                # Check if it looks like a function declaration/definition
                if '(' in line and ')' in line:
                    # Extract function signature
                    match = re.search(r'([a-zA-Z_]\w*)\s*\([^)]*\)', line)
                    if match:
                        func_name = match.group(1)
                        
                        # Skip common non-function keywords
                        if func_name in ['if', 'while', 'for', 'switch', 'return', 'typedef', 'struct', 'union', 'enum']:
                            i += 1
                            continue
                        
                        # Check if documented (look backwards for @brief)
                        documented = False
                        for j in range(max(0, i - 15), i):
                            if re.search(doxy_pattern, lines[j]):
                                documented = True
                                break
                        
                        if not documented:
                            # This is an undocumented function
                            results[str(rel_path)].append({
                                'name': func_name,
                                'line': i + 1,
                                'code': line.strip()
                            })
            i += 1
    
    return results

if __name__ == '__main__':
    undocumented = scan_files()
    
    total = 0
    print("=" * 80)
    print("UNDOCUMENTED FUNCTIONS REPORT")
    print("=" * 80)
    
    for filepath in sorted(undocumented.keys()):
        funcs = undocumented[filepath]
        if funcs:
            print(f"\n{filepath}")
            print("-" * 80)
            for func in funcs:
                print(f"  Line {func['line']:4d}: {func['name']:30s} | {func['code'][:60]}")
                total += 1
    
    print("\n" + "=" * 80)
    print(f"Total undocumented functions: {total}")
    print("=" * 80)
