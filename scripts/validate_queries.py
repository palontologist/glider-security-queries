#!/usr/bin/env python3
"""
Validate Glider query syntax and basic structure.
Usage: python scripts/validate_queries.py
"""

import ast
import sys
from pathlib import Path
import importlib.util

REQUIRED_DOCSTRING_FIELDS = ["@title", "@description", "@tags", "@references"]

def validate_syntax(filepath):
    """Check Python syntax."""
    try:
        with open(filepath, 'r') as f:
            source = f.read()
        ast.parse(source)
        return True, None
    except SyntaxError as e:
        return False, f"Syntax error: {e}"

def validate_structure(filepath):
    """Check query has required structure."""
    with open(filepath, 'r') as f:
        source = f.read()
    
    issues = []
    
    # Check for query() function
    if "def query():" not in source:
        issues.append("Missing 'def query():' function")
    
    # Check docstring fields
    for field in REQUIRED_DOCSTRING_FIELDS:
        if field not in source:
            issues.append(f"Missing required docstring field: {field}")
    
    # Check for Glider import
    if "from glider import *" not in source and "import glider" not in source:
        issues.append("Missing 'from glider import *' import")
    
    return len(issues) == 0, issues

def validate_imports(filepath):
    """Check query can be imported without errors."""
    try:
        spec = importlib.util.spec_from_file_location("query_module", filepath)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Check query() exists and is callable
        if not hasattr(module, 'query') or not callable(module.query):
            return False, ["query() function not found or not callable"]
        
        # Try calling query()
        try:
            result = module.query()
            if result is None:
                return False, ["query() returned None"]
        except Exception as e:
            return False, [f"query() execution error: {e}"]
        
        return True, None
    except Exception as e:
        return False, [f"Import error: {e}"]

def main():
    query_dir = Path("queries")
    if not query_dir.exists():
        print("Error: queries/ directory not found")
        sys.exit(1)
    
    query_files = list(query_dir.rglob("*.py"))
    print(f"Validating {len(query_files)} queries...\n")
    
    all_passed = True
    
    for query_file in query_files:
        print(f"Checking {query_file.relative_to(query_dir)}...")
        
        # Syntax check
        ok, err = validate_syntax(query_file)
        if not ok:
            print(f"  ✗ Syntax: {err}")
            all_passed = False
            continue
        print(f"  ✓ Syntax OK")
        
        # Structure check
        ok, issues = validate_structure(query_file)
        if not ok:
            for issue in issues:
                print(f"  ✗ Structure: {issue}")
            all_passed = False
        else:
            print(f"  ✓ Structure OK")
        
        # Import check
        ok, issues = validate_imports(query_file)
        if not ok:
            for issue in issues:
                print(f"  ✗ Import: {issue}")
            all_passed = False
        else:
            print(f"  ✓ Import OK")
        
        print()
    
    print("=" * 40)
    if all_passed:
        print("All queries validated successfully! ✓")
        sys.exit(0)
    else:
        print("Validation FAILED ✗")
        sys.exit(1)

if __name__ == "__main__":
    main()