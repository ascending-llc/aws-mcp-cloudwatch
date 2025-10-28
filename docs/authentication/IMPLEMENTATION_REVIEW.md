# Authentication Implementation Review

This document provides a comprehensive overview of all changes made to implement IAM Identity Center authentication for the CloudWatch MCP Server.

## Summary

The CloudWatch MCP Server has been updated to support IAM Identity Center (AWS SSO) authentication using a Starlette middleware pattern. The implementation allows for request-scoped AWS credentials while maintaining backward compatibility with local development using AWS profiles.

## Changes Made

### 1. New Files Created

#### middleware.py
**Location:** `cloudwatch_mcp_server/middleware.py`

**Purpose:** Implements Starlette middleware for IAM Identity Center authentication

**Key Features:**
- JWT token validation using AWS Identity Center's OIDC issuer
- AWS STS AssumeRole integration to exchange OIDC tokens for temporary credentials
- Request-scoped credential attachment via `request.state`
- Optional authentication (can be disabled via `ENABLE_AUTH=false` for local dev)
- Health check endpoint bypass

**Key Implementation Details:**
```python
class IAMIdentityCenterMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip health checks
        if request.url.path in ['/health', '/']:
            return await call_next(request)

        # Extract and verify JWT token
        token = self._extract_bearer_token(request)
        token_payload = await self._verify_token(token)

        # Assume role and get AWS credentials
        aws_credentials = await self._assume_role(token_payload)

        # Attach to request state
        request.state.aws_credentials = aws_credentials
        request.state.user_email = token_payload.get('email')

        return await call_next(request)
```

**Required Environment Variables:**
- `AWS_IDENTITY_CENTER_ISSUER` - OIDC issuer URL
- `AWS_IDENTITY_CENTER_CLIENT_ID` - OIDC application client ID
- `AWS_CLOUDWATCH_ROLE_ARN` - IAM role to assume
- `AWS_IDENTITY_CENTER_REGION` - Region (defaults to us-east-1)
- `ENABLE_AUTH` - Set to 'false' to disable authentication for local dev

#### IAM_IDENTITY_CENTER_SETUP.md
**Location:** `IAM_IDENTITY_CENTER_SETUP.md`

**Purpose:** Complete AWS CLI guide for setting up IAM Identity Center authentication

**Contents:**
- Step 1: Enable IAM Identity Center
- Step 2: Create OIDC Application with MCP server as trusted client
- Step 3: Create IAM Role with trust policy for OIDC federation
- Step 4: Attach CloudWatch read-only permissions
- Step 5: Assign users to the application
- Step 6: Configure environment variables
- Multi-account setup instructions
- Testing and validation steps

**Key Commands Included:**
- Creating OIDC applications
- IAM role creation with trust policies
- Permission assignments
- User/group assignments

### 2. Modified Files

#### pyproject.toml
**Changes:** Added JWT authentication dependencies

**Before:**
```toml
dependencies = [
    "boto3>=1.38.22",
    "loguru>=0.7.0",
    "fastmcp>=2.12.5",
    "mcp[cli]>=1.11.0",
    "pydantic>=2.10.6",
]
```

**After:**
```toml
dependencies = [
    "boto3>=1.38.22",
    "loguru>=0.7.0",
    "fastmcp>=2.12.5",
    "mcp[cli]>=1.11.0",
    "pydantic>=2.10.6",
    "pyjwt[crypto]>=2.8.0",
    "cryptography>=42.0.0",
]
```

**Impact:** Requires running `uv sync` to install new dependencies

#### server.py
**Changes:** Added IAMIdentityCenterMiddleware integration

**Location:** Lines 6, 16-21

**Code Added:**
```python
from cloudwatch_mcp_server.middleware import IAMIdentityCenterMiddleware

# Add authentication middleware
# Set ENABLE_AUTH=false for local development without authentication
enable_auth = os.getenv('ENABLE_AUTH', 'true').lower() == 'true'
mcp.add_middleware(IAMIdentityCenterMiddleware, enable_auth=enable_auth)

logger.info(f"Authentication {'enabled' if enable_auth else 'disabled'}")
```

**Impact:**
- Authentication is enabled by default
- Can be disabled for local development with `ENABLE_AUTH=false`
- Middleware runs before all tool handlers

#### cloudwatch_logs/tools.py
**Changes:** Updated to use request-scoped credentials

**Modified Method:** `_get_logs_client()` (Lines 46-87)

**Key Changes:**
1. Added `request_state` parameter to method signature
2. Check for authenticated credentials first
3. Fall back to AWS_PROFILE for local development
4. Added user email logging for audit trail

**Pattern Applied:**
```python
def _get_logs_client(self, region: str, request_state=None):
    """Create a CloudWatch Logs client."""
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
            logger.info(f"Using authenticated credentials for user: {getattr(request_state, 'user_email', 'unknown')}")
            return session.client('logs', config=config)

        # Fall back to profile-based auth for local development
        if aws_profile := os.environ.get('AWS_PROFILE'):
            return boto3.Session(profile_name=aws_profile, region_name=region).client('logs', config=config)
```

**Updated Tool Methods (5 total):**
1. `describe_log_groups` (Line 293)
2. `analyze_log_group` (Line 424)
3. `execute_log_insights_query` (Line 588)
4. `get_logs_insight_query_results` (Line 630)
5. `cancel_logs_insight_query` (Line 665)

**Call Pattern:**
```python
logs_client = self._get_logs_client(region, getattr(ctx, 'request_state', None))
```

#### cloudwatch_metrics/tools.py
**Changes:** Updated to use request-scoped credentials (same pattern as logs)

**Modified Method:** `_get_cloudwatch_client()` (Lines 46-86)

**Updated Tool Methods (1 total):**
1. `get_metric_data` (Line 374)

**Call Pattern:**
```python
cloudwatch_client = self._get_cloudwatch_client(region, getattr(ctx, 'request_state', None))
```

#### cloudwatch_alarms/tools.py
**Changes:** Updated to use request-scoped credentials (same pattern as logs/metrics)

**Modified Method:** `_get_cloudwatch_client()` (Lines 46-80)

**Updated Tool Methods (2 total):**
1. `get_active_alarms` (Line 142)
2. `get_alarm_history` (Line 295)

**Call Pattern:**
```python
cloudwatch_client = self._get_cloudwatch_client(region, getattr(ctx, 'request_state', None))
```

## Architecture Pattern

### Request Flow

1. **HTTP Request Arrives** → FastMCP receives request
2. **Middleware Execution** → IAMIdentityCenterMiddleware processes request:
   - Extracts Bearer token from Authorization header
   - Validates JWT token using AWS Identity Center's JWKS endpoint
   - Calls AWS STS AssumeRole with OIDC token
   - Attaches temporary credentials to `request.state`
3. **Tool Execution** → Tool handlers access credentials via `ctx.request_state`:
   - Create AWS SDK clients with temporary credentials
   - Execute CloudWatch API calls with user-specific credentials
4. **Response** → Results returned to client

### Credential Flow

```
User → OIDC Token → Middleware → STS AssumeRole → Temporary Creds → Request State → Tools → AWS APIs
```

### Backward Compatibility

The implementation maintains full backward compatibility:
- **With Authentication:** `ENABLE_AUTH=true` (default) - requires OIDC tokens
- **Without Authentication:** `ENABLE_AUTH=false` - uses AWS_PROFILE from environment
- **Local Development:** Disable auth and use local AWS profiles
- **Production:** Enable auth and use IAM Identity Center

## Security Considerations

### Token Validation
- JWT tokens are validated using AWS Identity Center's JWKS endpoint
- Tokens must have valid signatures, issuer, audience, and expiration
- PyJWKClient caches keys for performance

### Temporary Credentials
- Credentials are temporary (default 1 hour) and scoped to specific IAM role
- Credentials are request-scoped and not shared between requests
- STS session name includes timestamp for audit trail

### IAM Permissions
- Recommended to use CloudWatch read-only managed policy
- Principle of least privilege applies
- Multi-account support via cross-account trust relationships

### Audit Trail
- User email logged on each authenticated request
- CloudWatch API calls traceable to specific users via CloudTrail
- STS session names include timestamps for correlation

## Testing Requirements

### Before CI/CD Implementation

1. **Install Dependencies:**
```bash
uv sync
```

2. **Local Testing (Auth Disabled):**
```bash
export ENABLE_AUTH=false
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
uv run server.py
```

3. **Local Testing (Auth Enabled):**
```bash
export ENABLE_AUTH=true
export AWS_IDENTITY_CENTER_ISSUER=https://your-issuer
export AWS_IDENTITY_CENTER_CLIENT_ID=your-client-id
export AWS_CLOUDWATCH_ROLE_ARN=arn:aws:iam::123456789012:role/CloudWatchMCPRole
export AWS_IDENTITY_CENTER_REGION=us-east-1
uv run server.py
```

4. **Docker Testing:**
```bash
docker build -t cloudwatch-mcp-server .
docker run -p 3334:3334 \
  -e ENABLE_AUTH=true \
  -e AWS_IDENTITY_CENTER_ISSUER=https://your-issuer \
  -e AWS_IDENTITY_CENTER_CLIENT_ID=your-client-id \
  -e AWS_CLOUDWATCH_ROLE_ARN=arn:aws:iam::123456789012:role/CloudWatchMCPRole \
  cloudwatch-mcp-server
```

### Test Cases

1. **Health Check (No Auth Required):**
```bash
curl http://localhost:3334/health
```

2. **Tool Call (Auth Required):**
```bash
curl -X POST http://localhost:3334/mcp/tools/call \
  -H "Authorization: Bearer <your-oidc-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "get_active_alarms", "arguments": {}}'
```

3. **Verify Credentials Used:**
Check logs for "Using authenticated credentials for user: user@example.com"

## Next Steps (CI/CD - Pending)

### GitHub Actions Workflows

1. **`.github/workflows/test.yml`** - Run tests, linting, type checking
2. **`.github/workflows/build.yml`** - Build and push Docker images
3. **`.github/workflows/deploy-test.yml`** - Deploy to test server

### Docker Compose

Create `docker-compose.yml` for easy deployment:
```yaml
services:
  cloudwatch-mcp-server:
    image: cloudwatch-mcp-server:latest
    ports:
      - "3334:3334"
    environment:
      - ENABLE_AUTH=true
      - AWS_IDENTITY_CENTER_ISSUER=${AWS_IDENTITY_CENTER_ISSUER}
      - AWS_IDENTITY_CENTER_CLIENT_ID=${AWS_IDENTITY_CENTER_CLIENT_ID}
      - AWS_CLOUDWATCH_ROLE_ARN=${AWS_CLOUDWATCH_ROLE_ARN}
      - AWS_IDENTITY_CENTER_REGION=${AWS_IDENTITY_CENTER_REGION}
```

### Documentation Updates

1. Update README.md with authentication setup instructions
2. Update DEPLOYMENT.md with complete deployment guide
3. Create TROUBLESHOOTING.md for common authentication issues

## Summary of Files Changed

### New Files (2)
- `cloudwatch_mcp_server/middleware.py` - Authentication middleware
- `IAM_IDENTITY_CENTER_SETUP.md` - AWS setup guide

### Modified Files (5)
- `pyproject.toml` - Added JWT dependencies
- `cloudwatch_mcp_server/server.py` - Added middleware integration
- `cloudwatch_mcp_server/cloudwatch_logs/tools.py` - Updated client creation (5 tools)
- `cloudwatch_mcp_server/cloudwatch_metrics/tools.py` - Updated client creation (1 tool)
- `cloudwatch_mcp_server/cloudwatch_alarms/tools.py` - Updated client creation (2 tools)

### Total Tools Updated: 8

## Review Checklist

- [ ] Review middleware.py implementation for security concerns
- [ ] Review IAM_IDENTITY_CENTER_SETUP.md for completeness
- [ ] Verify pyproject.toml dependencies are acceptable
- [ ] Review server.py middleware integration
- [ ] Verify cloudwatch_logs/tools.py credential handling
- [ ] Verify cloudwatch_metrics/tools.py credential handling
- [ ] Verify cloudwatch_alarms/tools.py credential handling
- [ ] Test locally with auth disabled (AWS_PROFILE)
- [ ] Test locally with auth enabled (OIDC token)
- [ ] Review environment variable requirements
- [ ] Approve proceeding with CI/CD implementation

## Questions for Review

1. **Security:** Are the token validation and credential handling secure enough?
2. **Multi-Account:** Should we implement multi-account support now or later?
3. **Error Handling:** Are error messages appropriate (not leaking sensitive info)?
4. **Logging:** Is the audit trail logging sufficient?
5. **Testing:** What additional testing is needed before production?
6. **CI/CD:** Are there specific CI/CD requirements or constraints?
7. **Deployment:** What is the target deployment environment?

## Approval

Once reviewed and approved, we will proceed with:
1. Creating GitHub Actions workflows
2. Updating documentation
3. Creating deployment configurations
4. Setting up test environment

---

**Status:** Ready for Review
**Date:** 2025-01-27
**Next Phase:** CI/CD Implementation (pending approval)
