#!/bin/bash
# Test script for CloudWatch MCP Server Docker with HTTP transport

set -e

echo "=== CloudWatch MCP Server Docker HTTP Test ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="cloudwatch-mcp-server"
CONTAINER_NAME="cloudwatch-mcp-test"
PORT=3334

echo -e "${YELLOW}Step 1: Building Docker image...${NC}"
docker build -t $IMAGE_NAME .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Docker image built successfully${NC}"
else
    echo -e "${RED}✗ Failed to build Docker image${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Step 2: Checking for existing container...${NC}"
if docker ps -a | grep -q $CONTAINER_NAME; then
    echo "Removing existing container..."
    docker rm -f $CONTAINER_NAME
fi

echo ""
echo -e "${YELLOW}Step 3: Starting container with HTTP transport...${NC}"
docker run -d \
    --name $CONTAINER_NAME \
    -p $PORT:$PORT \
    -e AWS_REGION=${AWS_REGION:-us-east-1} \
    -e AWS_PROFILE=${AWS_PROFILE:-default} \
    -e FASTMCP_LOG_LEVEL=INFO \
    -e CLOUDWATCH_MCP_PORT=$PORT \
    -e CLOUDWATCH_MCP_SERVER_HOST=0.0.0.0 \
    -v ~/.aws:/root/.aws:ro \
    $IMAGE_NAME

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Container started successfully${NC}"
else
    echo -e "${RED}✗ Failed to start container${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Step 4: Waiting for server to be ready...${NC}"
sleep 5

# Check if container is still running
if docker ps | grep -q $CONTAINER_NAME; then
    echo -e "${GREEN}✓ Container is running${NC}"
else
    echo -e "${RED}✗ Container stopped unexpectedly${NC}"
    echo "Container logs:"
    docker logs $CONTAINER_NAME
    docker rm -f $CONTAINER_NAME
    exit 1
fi

echo ""
echo -e "${YELLOW}Step 5: Testing HTTP endpoints...${NC}"

# Test health/info endpoint
echo "Testing server info endpoint..."
RESPONSE=$(curl -s -w "\n%{http_code}" http://localhost:$PORT/ || echo "000")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "404" ]; then
    echo -e "${GREEN}✓ Server is responding${NC}"
    echo "Response: $BODY"
else
    echo -e "${RED}✗ Server not responding correctly (HTTP $HTTP_CODE)${NC}"
fi

echo ""
echo -e "${YELLOW}Step 6: Viewing container logs...${NC}"
docker logs --tail 50 $CONTAINER_NAME

echo ""
echo -e "${GREEN}=== Test Complete ===${NC}"
echo ""
echo "Container is running. You can:"
echo "  - View logs: docker logs -f $CONTAINER_NAME"
echo "  - Stop container: docker stop $CONTAINER_NAME"
echo "  - Remove container: docker rm -f $CONTAINER_NAME"
echo ""
echo "To test MCP tools, you can use curl or the MCP Inspector:"
echo "  curl http://localhost:$PORT/"
echo ""
