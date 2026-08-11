#!/usr/bin/env python3
"""
Run all Glider queries against a target directory.
Usage: python scripts/run_all_queries.py --target ./examples --output results/
"""

import argparse
import subprocess
import sys
from pathlib import Path
import json
import time

def find_queries(query_dir):
    """Find all .py query files."""
    return list(Path(query_dir).rglob("*.py"))

def run_query(query_path, target, output_dir, format="json"):
    """Run a single Glider query."""
    output_file = output_dir / f"{query_path.stem}.{format}"
    
    cmd = [
        "glider", "run", str(query_path),
        "--target", target,
        "--format", format,
        "--output", str(output_file)
    ]
    
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start
    
    return {
        "query": str(query_path),
        "success": result.returncode == 0,
        "time": elapsed,
        "output": output_file,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    }

def main():
    parser = argparse.ArgumentParser(description="Run all Glider queries")
    parser.add_argument("--target", required=True, help="Target directory or contract address")
    parser.add_argument("--output", default="results", help="Output directory")
    parser.add_argument("--queries", default="queries", help="Queries directory")
    parser.add_argument("--format", default="json", choices=["json", "sarif", "csv"], help="Output format")
    parser.add_argument("--parallel", type=int, default=1, help="Parallel jobs")
    args = parser.parse_args()
    
    # Setup
    query_dir = Path(args.queries)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find queries
    queries = find_queries(query_dir)
    print(f"Found {len(queries)} queries")
    
    # Run queries
    results = []
    for i, query in enumerate(queries, 1):
        print(f"[{i}/{len(queries)}] Running {query.relative_to(query_dir)}...")
        result = run_query(query, args.target, output_dir, args.format)
        results.append(result)
        
        status = "✓" if result["success"] else "✗"
        print(f"  {status} {result['time']:.1f}s")
        if not result["success"]:
            print(f"    Error: {result['stderr'][:200]}")
    
    # Summary
    successful = sum(1 for r in results if r["success"])
    print(f"\n=== Summary ===")
    print(f"Total: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {len(results) - successful}")
    print(f"Total time: {sum(r['time'] for r in results):.1f}s")
    
    # Save summary
    summary_file = output_dir / "summary.json"
    with open(summary_file, "w") as f:
        json.dump({
            "target": args.target,
            "total": len(results),
            "successful": successful,
            "failed": len(results) - successful,
            "results": results
        }, f, indent=2)
    
    print(f"Summary saved to {summary_file}")
    
    # Exit code
    sys.exit(0 if successful == len(results) else 1)

if __name__ == "__main__":
    main()