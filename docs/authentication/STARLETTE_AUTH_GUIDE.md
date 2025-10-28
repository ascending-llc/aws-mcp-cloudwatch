# Starlette Middleware Authentication Guide

## Why Starlette Middleware is the Best Approach for FastMCP

### ✅ Advantages

1. **Clean Separation of Concerns**
   - Authentication logic is separate from business logic
   - No need to modify every tool handler
   - Middleware runs before any MCP tool is called

2. **Request Context Pattern**
   - Attach AWS credentials to `request.state`
   - All downstream handlers automatically have access
   - No global state or thread locals needed

3. **FastMCP Native Support**
   - FastMCP is built on FastAPI/Starlette
   - Middleware integrates seamlessly via `mcp.add_middleware()`
   - Works with all transport types (stdio, HTTP, SSE)

4. **Testability**
   - Easy to disable auth for local development
   - Can mock `request.state` in tests
   - Clear interface between auth and business logic

5. **Performance**
   - Token validation cached via PyJWKClient
   - AWS credentials cached on request object
   - Single auth check per request, not per tool

---

## How to Integrate with server.py

### Step 1: Update server.py

```python
import os
from cloudwatch_mcp_server.cloudwatch_alarms.tools import CloudWatchAlarmsTools
from cloudwatch_mcp_server.cloudwatch_logs.tools import CloudWatchLogsTools
from cloudwatch_mcp_server.cloudwatch_metrics.tools import CloudWatchMetricsTools
from cloudwatch_mcp_server.middleware import CognitoAuthMiddleware
from loguru import logger
from fastmcp import FastMCP


mcp = FastMCP(
    'cloudwatch-mcp-server',
    instructions='Use this MCP server to run read-only commands and analyze CloudWatch Logs, Metrics, and Alarms...',
)

# Add authentication middleware
# Set enable_auth=False for local development without auth
enable_auth = os.getenv('ENABLE_AUTH', 'true').lower() == 'true'
mcp.add_middleware(CognitoAuthMiddleware, enable_auth=enable_auth)

logger.info(f"Authentication {'enabled' if enable_auth else 'disabled'}")

# Initialize and register CloudWatch tools
try:
    cloudwatch_logs_tools = CloudWatchLogsTools()
    cloudwatch_logs_tools.register(mcp)
    logger.info('CloudWatch Logs tools registered successfully')

    cloudwatch_metrics_tools = CloudWatchMetricsTools()
    cloudwatch_metrics_tools.register(mcp)
    logger.info('CloudWatch Metrics tools registered successfully')

    cloudwatch_alarms_tools = CloudWatchAlarmsTools()
    cloudwatch_alarms_tools.register(mcp)
    logger.info('CloudWatch Alarms tools registered successfully')
except Exception as e:
    logger.error(f'Error initializing CloudWatch tools: {str(e)}')
    raise


def main():
    """Run the MCP server."""
    logger.info("Initializing CloudWatch MCP server...")
    logger.info("AWS_PROFILE=%s  AWS_REGION=%s", os.getenv("AWS_PROFILE"), os.getenv("AWS_REGION"))
    host = os.getenv("CLOUDWATCH_MCP_SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("CLOUDWATCH_MCP_PORT", "3334"))

    mcp.run(transport="streamable-http", host=host, port=port)

    logger.info('CloudWatch MCP server started')


if __name__ == '__main__':
    main()
```

### Step 2: Update Tools to Use Request Credentials

Modify your tools to use the AWS credentials from `request.state` when available:

**Example: cloudwatch_logs/tools.py**

```python
class CloudWatchLogsTools:
    """CloudWatch Logs tools for MCP server."""

    def __init__(self):
        """Initialize the CloudWatch Logs tools."""
        self._logs_client = None
        self._logs_client_region = None

    def _get_logs_client(self, region: str, request_state=None):
        """Create a CloudWatch Logs client.

        Args:
            region: AWS region
            request_state: Optional request state with AWS credentials
        """
        config = Config(user_agent_extra=f'awslabs/mcp/cloudwatch-mcp-server/{MCP_SERVER_VERSION}')

        try:
            # If request has authenticated credentials, use them
            if request_state and hasattr(request_state, 'aws_credentials'):
                creds = request_state.aws_credentials
                session = boto3.Session(
                    aws_access_key_id=creds['access_key_id'],
                    aws_secret_access_key=creds['secret_access_key'],
                    aws_session_token=creds['session_token'],
                    region_name=region
                )
                logger.info(f"Using authenticated credentials for user: {request_state.user_email}")
                return session.client('logs', config=config)

            # Fall back to profile-based auth for local development
            if aws_profile := os.environ.get('AWS_PROFILE'):
                return boto3.Session(
                    profile_name=aws_profile,
                    region_name=region
                ).client('logs', config=config)
            else:
                return boto3.Session(region_name=region).client('logs', config=config)

        except Exception as e:
            logger.error(f'Error creating cloudwatch logs client for region {region}: {str(e)}')
            raise

    # Update tool methods to accept and pass request context
    async def describe_log_groups(
        self,
        ctx: Context,
        region: str = 'us-east-1',
        # ... other params
    ) -> LogsMetadata:
        """Describe log groups with authenticated credentials."""

        # Access request state from MCP context
        request_state = getattr(ctx, 'request_state', None)

        # Get client with credentials from request
        logs_client = self._get_logs_client(region, request_state)

        # ... rest of implementation
```

**Key Pattern**:
- Pass `ctx.request_state` to any method that creates AWS clients
- The middleware attaches credentials to `request.state`
- FastMCP exposes this as `ctx.request_state` in tool handlers

---

## Environment Variables

### Required for Cognito Authentication

```bash
# Enable/disable authentication
ENABLE_AUTH=true

# Cognito User Pool configuration
AWS_COGNITO_REGION=us-east-1
AWS_COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
AWS_COGNITO_CLIENT_ID=your-client-id

# Cognito Identity Pool for AWS credential exchange
AWS_COGNITO_IDENTITY_POOL_ID=us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Optional: Logging
FASTMCP_LOG_LEVEL=INFO
```

### For IAM Identity Center

```bash
ENABLE_AUTH=true
AWS_IDENTITY_CENTER_REGION=us-east-1
AWS_IDENTITY_CENTER_ISSUER=https://xxxxxxxx.awsapps.com/start
AWS_IDENTITY_CENTER_CLIENT_ID=your-client-id
AWS_CLOUDWATCH_ROLE_ARN=arn:aws:iam::ACCOUNT-ID:role/CloudWatchMCPRole
```

### For Generic OIDC (Okta, Auth0, etc.)

```bash
ENABLE_AUTH=true
OIDC_ISSUER=https://your-domain.okta.com
OIDC_CLIENT_ID=your-client-id
AWS_CLOUDWATCH_ROLE_ARN=arn:aws:iam::ACCOUNT-ID:role/CloudWatchMCPRole
```

---

## Update pyproject.toml Dependencies

Add JWT and crypto dependencies:

```toml
[project]
dependencies = [
    "boto3>=1.38.22",
    "loguru>=0.7.0",
    "fastmcp>=2.12.5",
    "mcp[cli]>=1.11.0",
    "pydantic>=2.10.6",
    # Add these for authentication
    "pyjwt[crypto]>=2.8.0",
    "cryptography>=42.0.0",
]
```

---

## Docker Integration

### Update Dockerfile to Include Dependencies

The Dockerfile already uses `uv sync`, so dependencies from `pyproject.toml` will be installed automatically.

### Update docker-compose.yml (Optional)

```yaml
version: '3.8'
services:
  cloudwatch-mcp:
    build: .
    ports:
      - "3334:3334"
    environment:
      # Authentication
      - ENABLE_AUTH=true
      - AWS_COGNITO_REGION=us-east-1
      - AWS_COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID}
      - AWS_COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID}
      - AWS_COGNITO_IDENTITY_POOL_ID=${COGNITO_IDENTITY_POOL_ID}

      # Server config
      - CLOUDWATCH_MCP_PORT=3334
      - CLOUDWATCH_MCP_SERVER_HOST=0.0.0.0
      - FASTMCP_LOG_LEVEL=INFO
```

---

## Testing

### Test Without Authentication (Local Development)

```bash
# Disable auth for local testing
export ENABLE_AUTH=false
uv run server.py
```

### Test With Mock Authentication (Unit Tests)

```python
# tests/test_auth_middleware.py
import pytest
from starlette.testclient import TestClient
from cloudwatch_mcp_server.server import mcp

@pytest.fixture
def client():
    return TestClient(mcp.http_app)

def test_unauthenticated_request_blocked(client):
    """Test that requests without auth are blocked."""
    response = client.post("/mcp", json={})
    assert response.status_code == 401

def test_authenticated_request_allowed(client, mock_jwt_token):
    """Test that authenticated requests proceed."""
    headers = {"Authorization": f"Bearer {mock_jwt_token}"}
    response = client.post("/mcp", json={}, headers=headers)
    assert response.status_code != 401
```

### Integration Test With Real Cognito

```python
import requests
import boto3

# Get Cognito token
cognito_client = boto3.client('cognito-idp', region_name='us-east-1')
response = cognito_client.initiate_auth(
    ClientId='your-client-id',
    AuthFlow='USER_PASSWORD_AUTH',
    AuthParameters={
        'USERNAME': 'test@example.com',
        'PASSWORD': 'YourPassword123!'
    }
)

access_token = response['AuthenticationResult']['AccessToken']

# Test MCP server
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.post(
    'http://localhost:3334/mcp',
    json={
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 1
    },
    headers=headers
)

print(response.json())
```

---

## How Credentials Flow Through the System

```
1. User sends request with JWT token
   ↓
2. Starlette middleware intercepts request
   ↓
3. Middleware validates JWT token
   ↓
4. Middleware exchanges JWT for AWS credentials
   ↓
5. Middleware attaches credentials to request.state
   ↓
6. FastMCP processes MCP request
   ↓
7. MCP tool handler is called
   ↓
8. Tool accesses ctx.request_state.aws_credentials
   ↓
9. Tool creates boto3 client with credentials
   ↓
10. Tool calls CloudWatch API
    ↓
11. Response flows back to user
```

---

## Comparison: Middleware vs Other Approaches

| Approach | Pros | Cons |
|----------|------|------|
| **Starlette Middleware** ✅ | Clean, FastMCP native, testable | Requires FastMCP 2.x |
| Dependency Injection | Type-safe | Verbose, repeat in every tool |
| Decorator Pattern | Reusable | Harder to test, scattered logic |
| Global State | Simple | Thread-unsafe, testing nightmare |
| Context Manager | Pythonic | Awkward with async/await |

---

## Security Best Practices

1. **Always validate tokens** - Never skip JWT verification
2. **Use short-lived credentials** - 1-hour max via Cognito/STS
3. **Log authentication events** - Monitor for suspicious activity
4. **Rate limit requests** - Prevent abuse
5. **Rotate secrets** - Regularly update client secrets
6. **Use HTTPS in production** - Never send tokens over HTTP
7. **Implement token refresh** - Handle expired tokens gracefully

---

## Troubleshooting

### "Missing Authorization header" Error

**Cause**: Request doesn't include `Authorization: Bearer <token>` header

**Solution**:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" http://localhost:3334/mcp
```

### "Invalid token" Error

**Causes**:
1. Token expired (>1 hour old)
2. Token from wrong user pool
3. Token signature verification failed

**Solution**: Get a fresh token from Cognito

### "Authentication failed" Error (500)

**Cause**: Error in credential exchange process

**Debug**:
```bash
# Check logs
docker logs cloudwatch-mcp-test

# Verify Cognito Identity Pool is configured
aws cognito-identity describe-identity-pool \
  --identity-pool-id YOUR_POOL_ID
```

### Tools Still Use Wrong Credentials

**Cause**: Tools not updated to use `request.state`

**Solution**: Update tool methods to accept and pass `ctx.request_state`

---

## Next Steps

1. **Choose auth provider** (Cognito recommended)
2. **Set up infrastructure** (CloudFormation/Terraform)
3. **Update server.py** to add middleware
4. **Update tools** to use request credentials
5. **Add dependencies** to pyproject.toml
6. **Test locally** with ENABLE_AUTH=false
7. **Test with auth** using real Cognito tokens
8. **Deploy to test environment**

---

## Summary

**Starlette middleware is the idiomatic and recommended approach** for authentication in FastMCP because:

✅ Clean separation of concerns
✅ Native FastMCP integration
✅ Easy to test and maintain
✅ Request-scoped credentials
✅ No global state
✅ Works with all transports

The middleware handles:
- JWT token validation
- AWS credential vending
- Request state management
- Error handling
- Logging

Your tools simply access `ctx.request_state.aws_credentials` - that's it!
