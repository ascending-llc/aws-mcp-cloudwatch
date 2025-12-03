#!/usr/bin/env python3
"""Local test script for CloudWatch MCP truncation functionality."""

import httpx
import json
import sys
from datetime import datetime, timedelta

# MCP server configuration
MCP_SERVER_URL = "http://localhost:3334/mcp"

def call_mcp_tool(tool_name: str, arguments: dict):
    """Call an MCP tool via HTTP transport."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream"
    }

    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(MCP_SERVER_URL, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        print(f"Error calling tool: {e}")
        return None

def test_default_limit():
    """Test 1: Query with no limit specified (should default to 100)."""
    print("\n" + "="*80)
    print("TEST 1: Default Limit Enforcement")
    print("="*80)

    # Use times from 24 hours ago to now
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)

    arguments = {
        "start_time": start_time.isoformat() + "+00:00",
        "end_time": end_time.isoformat() + "+00:00",
        "log_group_names": ["/aws/containerinsights/ascending-s-api-cluster/application"],
        "query_string": "fields @timestamp, @message | sort @timestamp desc",
        "region": "us-east-1"
    }

    print(f"Query: {arguments['query_string']}")
    print("No limit specified - should default to 100")

    result = call_mcp_tool("execute_log_insights_query", arguments)

    if result and "result" in result:
        content = result["result"].get("content", [])
        if content:
            data = json.loads(content[0].get("text", "{}"))
            metadata = data.get("truncation_metadata", {})
            print(f"\n✓ Query completed successfully")
            print(f"  - Status: {data.get('status')}")
            print(f"  - Results returned: {metadata.get('results_returned', 'N/A')}")
            print(f"  - Total available: {metadata.get('total_results_available', 'N/A')}")
            print(f"  - Field truncations: {metadata.get('field_truncations', 0)}")
            print(f"  - Results truncated: {metadata.get('results_truncated', False)}")
            return True
    else:
        print(f"✗ Query failed: {result}")
        return False

def test_high_limit():
    """Test 2: Query with limit=1000 (should warn but allow)."""
    print("\n" + "="*80)
    print("TEST 2: High Limit Warning")
    print("="*80)

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)

    arguments = {
        "start_time": start_time.isoformat() + "+00:00",
        "end_time": end_time.isoformat() + "+00:00",
        "log_group_names": ["/aws/containerinsights/ascending-s-api-cluster/application"],
        "query_string": "fields @timestamp, @message | sort @timestamp desc | limit 1000",
        "limit": 1000,
        "region": "us-east-1"
    }

    print(f"Query: {arguments['query_string']}")
    print("Limit: 1000 (exceeds recommended 500 - should warn)")

    result = call_mcp_tool("execute_log_insights_query", arguments)

    if result and "result" in result:
        content = result["result"].get("content", [])
        if content:
            data = json.loads(content[0].get("text", "{}"))
            metadata = data.get("truncation_metadata", {})
            print(f"\n✓ Query completed")
            print(f"  - Results returned: {metadata.get('results_returned', 'N/A')}")
            print(f"  - Check Docker logs for warning about exceeding recommended limit")
            return True
    else:
        print(f"✗ Query failed: {result}")
        return False

def test_weaviate_query():
    """Test 3: Your actual Weaviate query."""
    print("\n" + "="*80)
    print("TEST 3: Weaviate Compaction Query")
    print("="*80)

    arguments = {
        "start_time": "2025-11-04T20:09:20+00:00",
        "end_time": "2025-11-05T20:09:20+00:00",
        "log_group_names": ["/aws/containerinsights/ascending-s-api-cluster/application"],
        "query_string": "fields @timestamp, @message, kubernetes.pod_name, log_processed.class, log_processed.index, log_processed.event, log_processed.shard | filter @message like /compaction_skipped_oom/ OR @message like /not enough memory/ | filter kubernetes.pod_name = \"weaviate-0\" | sort @timestamp desc | limit 400",
        "limit": 400,
        "region": "us-east-1"
    }

    print("Testing your actual query with limit=400")

    result = call_mcp_tool("execute_log_insights_query", arguments)

    if result and "result" in result:
        content = result["result"].get("content", [])
        if content:
            data = json.loads(content[0].get("text", "{}"))
            metadata = data.get("truncation_metadata", {})
            print(f"\n✓ Query completed successfully")
            print(f"  - Status: {data.get('status')}")
            print(f"  - Results returned: {metadata.get('results_returned', 'N/A')}")
            print(f"  - Total available: {metadata.get('total_results_available', 'N/A')}")
            print(f"  - Field truncations: {metadata.get('field_truncations', 0)}")
            print(f"  - Results truncated: {metadata.get('results_truncated', False)}")

            # Show sample result if available
            results = data.get("results", [])
            if results:
                print(f"\n  Sample result (first entry):")
                first_result = results[0]
                for key, value in first_result.items():
                    display_value = value[:100] + "..." if len(value) > 100 else value
                    print(f"    {key}: {display_value}")

            return True
    else:
        print(f"✗ Query failed: {result}")
        return False

def main():
    """Run all truncation tests."""
    print("\n" + "="*80)
    print("CloudWatch MCP Server - Truncation Testing")
    print("="*80)
    print(f"Server: {MCP_SERVER_URL}")
    print("Testing adaptive truncation functionality...\n")

    tests = [
        ("Default Limit", test_default_limit),
        ("High Limit Warning", test_high_limit),
        ("Weaviate Query", test_weaviate_query),
    ]

    results = []
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            print(f"\n✗ Test failed with exception: {e}")
            results.append((name, False))

    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    for name, success in results:
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"{status}: {name}")

    passed = sum(1 for _, success in results if success)
    total = len(results)
    print(f"\nTotal: {passed}/{total} tests passed")

    # Also suggest checking logs
    print("\n" + "="*80)
    print("Check Docker logs for detailed truncation info:")
    print("  docker logs -f cloudwatch-mcp-local | grep -E '(limit enforcement|Truncated)' ")
    print("="*80)

    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
