#!/bin/bash

# Test MCP Server with describe_log_groups

echo "Testing MCP Server at http://localhost:3334/mcp"
echo ""

# Initialize session
echo "1. Initializing session..."
INIT_RESPONSE=$(curl -s -X POST http://localhost:3334/mcp \
  --header "Content-Type: application/json" \
  --header "Accept: application/json, text/event-stream" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}')

echo "Response:"
echo "$INIT_RESPONSE" | grep -o '"serverInfo":{[^}]*}' || echo "$INIT_RESPONSE"
echo ""

# List tools
echo "2. Listing available tools..."
TOOLS_RESPONSE=$(curl -s -X POST http://localhost:3334/mcp \
  --header "Content-Type: application/json" \
  --header "Accept: application/json, text/event-stream" \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')

echo "Tools found:"
echo "$TOOLS_RESPONSE" | grep -o '"name":"[^"]*"' | head -10
echo ""

# Call describe_log_groups
echo "3. Calling describe_log_groups..."
TOOL_RESPONSE=$(curl -s -X POST http://localhost:3334/mcp \
  --header "Content-Type: application/json" \
  --header "Accept: application/json, text/event-stream" \
  --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"describe_log_groups","arguments":{"log_group_name_prefix":"/aws/","max_items":3,"region":"us-east-1"}}}')

echo "Response:"
echo "$TOOL_RESPONSE"
