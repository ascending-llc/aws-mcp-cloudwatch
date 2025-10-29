# CloudWatch MCP Server - OAuth Implementation Next Steps

## Overview

This document outlines the steps required to move from the current testing configuration (shared credentials, no authentication) to a production-ready OAuth implementation where users sign in with their own AWS credentials through the jarvis-demo site.

## Current State vs. Target State

### Current Testing Configuration
- **Authentication:** Disabled (`ENABLE_AUTH=false`)
- **AWS Credentials:** Single shared SSO credential set (saas profile)
- **User Access:** All users share same AWS account access
- **Credential Lifecycle:** Manual refresh every hour via script
- **Security:** Not production-ready

### Target Production Configuration
- **Authentication:** OAuth-enabled with OIDC token validation
- **AWS Credentials:** Per-user AWS credentials via IAM Identity Center (SSO)
- **User Access:** Each user accesses their own AWS resources
- **Credential Lifecycle:** Automatic token refresh via OAuth
- **Security:** Production-ready with proper authentication and authorization

## Architecture Overview

### OAuth Flow for AWS Credential Propagation

```
┌─────────────┐         ┌──────────────┐         ┌─────────────────┐
│             │         │              │         │                 │
│  User's     │         │  LibreChat   │         │  CloudWatch     │
│  Browser    │         │  (jarvis-api)│         │  MCP Server     │
│             │         │              │         │                 │
└──────┬──────┘         └──────┬───────┘         └────────┬────────┘
       │                       │                          │
       │  1. Login with OAuth  │                          │
       ├──────────────────────>│                          │
       │                       │                          │
       │  2. Redirect to IdP   │                          │
       │<──────────────────────┤                          │
       │                       │                          │
       │  3. Authenticate      │                          │
       │  & Authorize          │                          │
       │                       │                          │
       │  4. Return tokens     │                          │
       ├──────────────────────>│                          │
       │                       │                          │
       │                       │  5. Extract AWS creds    │
       │                       │     from OIDC token      │
       │                       │                          │
       │  6. Make MCP request  │                          │
       │  with OIDC token      │                          │
       ├──────────────────────>│                          │
       │                       │                          │
       │                       │  7. Forward request with │
       │                       │     AWS credentials      │
       │                       ├─────────────────────────>│
       │                       │                          │
       │                       │  8. Assume role using    │
       │                       │     user credentials     │
       │                       │     ┌──────────┐         │
       │                       │     │   AWS    │         │
       │                       │     │   STS    │         │
       │                       │     └──────────┘         │
       │                       │                          │
       │                       │  9. Access CloudWatch    │
       │                       │     ┌──────────┐         │
       │                       │     │CloudWatch│         │
       │                       │     │   API    │         │
       │                       │     └──────────┘         │
       │                       │                          │
       │                       │  10. Return results      │
       │                       │<─────────────────────────┤
       │                       │                          │
       │  11. Display results  │                          │
       │<──────────────────────┤                          │
       │                       │                          │
```

## Implementation Roadmap

### Phase 1: OAuth Provider Configuration

#### 1.1 Choose OAuth Provider
Options for jarvis-demo:
- **AWS IAM Identity Center (SSO)** - Recommended for AWS-native integration
- **Azure AD** - If organization uses Microsoft
- **Okta** - Enterprise identity provider
- **Auth0** - Flexible third-party option

**Recommendation:** Use AWS IAM Identity Center since CloudWatch MCP is AWS-focused.

#### 1.2 Configure OAuth Application
In your chosen identity provider:

1. Register new OAuth 2.0 application
   - **Application Name:** Jarvis Demo - CloudWatch MCP
   - **Redirect URI:** `https://jarvis-demo.yourdomain.com/oauth/callback`
   - **Scopes Required:**
     - `openid` - Basic user identity
     - `email` - User email address
     - `profile` - User profile information
     - Custom scope for AWS credentials (if using IAM Identity Center)

2. Configure token settings
   - **Token Lifetime:** 1 hour (matching AWS STS token lifetime)
   - **Refresh Token:** Enabled
   - **Token Format:** JWT

3. Record configuration values
   - Client ID
   - Client Secret
   - Authorization endpoint
   - Token endpoint
   - User info endpoint
   - JWKS URI (for token validation)

#### 1.3 Configure AWS IAM Identity Center Integration
If using AWS IAM Identity Center:

1. Create custom OIDC application in IAM Identity Center
2. Map OIDC claims to AWS credentials
3. Configure permission sets for CloudWatch access
4. Set up automatic provisioning

### Phase 2: LibreChat (jarvis-api) Configuration

#### 2.1 Update LibreChat OAuth Configuration
File: `librechat.yaml` (in jarvis-demo ConfigMap)

```yaml
# OAuth Configuration
version: 1.2.0
cache: true

endpoints:
  custom:
    - name: "CloudWatch MCP"
      apiKey: "${CLOUDWATCH_MCP_API_KEY}"
      baseURL: "http://cloudwatch-mcp:3334/mcp"
      models:
        default:
          - "cloudwatch-assistant"
      titleConvo: true
      titleModel: "current_model"
      summarize: false
      summaryModel: "current_model"
      forcePrompt: false
      modelDisplayLabel: "CloudWatch MCP"

# MCP Servers with OAuth
mcpServers:
  cloudwatch:
    type: streamable-http
    url: http://cloudwatch-mcp:3334/mcp
    timeout: 120000
    # OAuth configuration
    auth:
      type: oauth
      tokenEndpoint: https://your-identity-provider.com/oauth/token
      authorizationEndpoint: https://your-identity-provider.com/oauth/authorize
      clientId: ${OAUTH_CLIENT_ID}
      clientSecret: ${OAUTH_CLIENT_SECRET}
      scopes:
        - openid
        - email
        - profile
        - aws:cloudwatch
    # Pass OAuth tokens to MCP server
    headers:
      Authorization: "Bearer {oauth_token}"
      X-User-Email: "{user_email}"
    serverInstructions: |
      # CloudWatch MCP Server Instructions
      You have access to AWS CloudWatch through this MCP server connection...
```

#### 2.2 Update jarvis-api Deployment
Add OAuth environment variables:

```yaml
env:
  - name: OAUTH_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: oauth-credentials
        key: client-id
  - name: OAUTH_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: oauth-credentials
        key: client-secret
  - name: OAUTH_REDIRECT_URI
    value: "https://jarvis-demo.yourdomain.com/oauth/callback"
  - name: ENABLE_OAUTH
    value: "true"
```

Create OAuth credentials secret:
```bash
# pragma: allowlist secret
kubectl create secret generic oauth-credentials \
  --from-literal=client-id='your-client-id' \
  --from-literal=client-secret='your-client-secret' \
  -n jarvis-demo
```

### Phase 3: CloudWatch MCP Server OAuth Implementation

#### 3.1 Enable Authentication
File: `k8s/jarvis-demo/deployment-oauth.yaml` (new file, based on deployment-no-auth.yaml)

```yaml
env:
  # Enable OAuth authentication
  - name: ENABLE_AUTH
    value: "true"

  # OAuth validation configuration
  - name: OAUTH_JWKS_URL
    value: "https://your-identity-provider.com/.well-known/jwks.json"
  - name: OAUTH_AUDIENCE
    value: "cloudwatch-mcp-server"
  - name: OAUTH_ISSUER
    value: "https://your-identity-provider.com"

  # AWS IAM Identity Center integration (if applicable)
  - name: AWS_IDENTITY_CENTER_REGION
    value: "us-east-1"
  - name: AWS_IDENTITY_CENTER_START_URL
    value: "https://ascending.awsapps.com/start"

  # Remove shared credentials
  # - name: AWS_PROFILE
  #   value: "saas"

  # CloudWatch configuration
  - name: AWS_REGION
    value: "us-east-1"
  - name: CLOUDWATCH_MCP_SERVER_HOST
    value: "0.0.0.0"
  - name: CLOUDWATCH_MCP_PORT
    value: "3334"

  # Logging
  - name: FASTMCP_LOG_LEVEL
    value: "INFO"

  # Set HOME for boto3
  - name: HOME
    value: "/home/app"

# Remove shared credential mount
# volumes:
#   - name: aws-credentials
#     secret:
#       secretName: aws-credentials
```

#### 3.2 Implement OAuth Token Validation
File: `src/cloudwatch-mcp-server/cloudwatch_mcp_server/auth.py` (new file)

```python
"""OAuth authentication and authorization for CloudWatch MCP Server."""

import os
import jwt
import boto3
from typing import Dict, Optional
from loguru import logger
from fastapi import HTTPException, Header
from datetime import datetime, timedelta


class OAuthValidator:
    """Validates OAuth tokens and extracts AWS credentials."""

    def __init__(self):
        """Initialize OAuth validator with configuration."""
        self.jwks_url = os.environ.get('OAUTH_JWKS_URL')
        self.audience = os.environ.get('OAUTH_AUDIENCE')
        self.issuer = os.environ.get('OAUTH_ISSUER')
        self.jwks_client = jwt.PyJWKClient(self.jwks_url)

    def validate_token(self, token: str) -> Dict:
        """
        Validate OAuth token and extract claims.

        Args:
            token: Bearer token from Authorization header

        Returns:
            Dict containing validated token claims

        Raises:
            HTTPException: If token is invalid
        """
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Validate token
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
            )

            logger.info(f"Token validated for user: {claims.get('email')}")
            return claims

        except jwt.ExpiredSignatureError:
            logger.error("Token has expired")
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {str(e)}")
            raise HTTPException(status_code=401, detail="Invalid token")

    def extract_aws_credentials(self, claims: Dict) -> Dict:
        """
        Extract AWS credentials from token claims.

        For IAM Identity Center integration, the token should contain:
        - aws_access_key_id
        - aws_secret_access_key
        - aws_session_token

        Args:
            claims: Validated token claims

        Returns:
            Dict containing AWS credentials
        """
        # Extract AWS credentials from claims
        aws_creds = {
            'access_key_id': claims.get('aws_access_key_id'),
            'secret_access_key': claims.get('aws_secret_access_key'),
            'session_token': claims.get('aws_session_token'),
        }

        # Validate credentials are present
        if not all(aws_creds.values()):
            logger.error("Token missing AWS credentials")
            raise HTTPException(
                status_code=401,
                detail="Token does not contain valid AWS credentials"
            )

        return aws_creds


async def authenticate_request(
    authorization: Optional[str] = Header(None),
    x_user_email: Optional[str] = Header(None)
) -> Dict:
    """
    FastMCP middleware for OAuth authentication.

    Args:
        authorization: Bearer token from Authorization header
        x_user_email: User email from X-User-Email header

    Returns:
        Dict containing user info and AWS credentials

    Raises:
        HTTPException: If authentication fails
    """
    # Check if authentication is enabled
    if os.environ.get('ENABLE_AUTH', 'false').lower() != 'true':
        logger.warning("Authentication is disabled - using fallback credentials")
        return None

    # Validate authorization header
    if not authorization or not authorization.startswith('Bearer '):
        logger.error("Missing or invalid authorization header")
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authorization header"
        )

    # Extract token
    token = authorization.replace('Bearer ', '')

    # Validate token and extract AWS credentials
    validator = OAuthValidator()
    claims = validator.validate_token(token)
    aws_credentials = validator.extract_aws_credentials(claims)

    return {
        'user_email': claims.get('email') or x_user_email,
        'user_name': claims.get('name'),
        'aws_credentials': aws_credentials,
    }
```

#### 3.3 Update Tool Methods to Use User Credentials
File: `src/cloudwatch-mcp-server/cloudwatch_mcp_server/cloudwatch_alarms/tools.py`

Update `_get_cloudwatch_client` to use authenticated credentials:

```python
def _get_cloudwatch_client(self, region: str, request_state=None):
    """Create a CloudWatch client for the specified region.

    Args:
        region: AWS region
        request_state: Request state with AWS credentials from authentication

    Returns:
        CloudWatch client
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
            logger.info(f"Using authenticated credentials for user: {getattr(request_state, 'user_email', 'unknown')}")
            return session.client('cloudwatch', config=config)

        # Fall back to profile-based auth for local development
        if aws_profile := os.environ.get('AWS_PROFILE'):
            logger.warning("Using fallback profile-based authentication")
            return boto3.Session(profile_name=aws_profile, region_name=region).client(
                'cloudwatch', config=config
            )
        else:
            raise ValueError("No AWS credentials available")

    except Exception as e:
        logger.error(f'Error creating cloudwatch client for region {region}: {str(e)}')
        raise
```

Update tool methods to pass request state:

```python
async def get_active_alarms(
    self,
    ctx: Context,
    max_items: int = 50,
    region: str = 'us-east-1',
) -> ActiveAlarmsResponse:
    """Get currently active CloudWatch alarms."""
    try:
        # Get authenticated credentials from context
        request_state = getattr(ctx, 'request_state', None)

        # Create client with user credentials
        cw = self._get_cloudwatch_client(region, request_state)

        # ... rest of implementation
```

#### 3.4 Update Server Initialization
File: `src/cloudwatch-mcp-server/cloudwatch_mcp_server/server.py`

```python
from cloudwatch_mcp_server.auth import authenticate_request

# Initialize FastMCP with authentication
mcp = FastMCP(
    name='cloudwatch-mcp-server',
    version=MCP_SERVER_VERSION,
    dependencies=['boto3', 'botocore'],
)

# Add authentication middleware if enabled
if os.environ.get('ENABLE_AUTH', 'false').lower() == 'true':
    logger.info("Authentication enabled - OAuth tokens will be validated")

    @mcp.middleware("http")
    async def auth_middleware(request, call_next):
        """Validate OAuth token and attach credentials to request."""
        try:
            auth_info = await authenticate_request(
                authorization=request.headers.get('authorization'),
                x_user_email=request.headers.get('x-user-email')
            )

            # Attach auth info to request state for tools to access
            request.state.request_state = type('RequestState', (), auth_info)()

        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.detail}
            )

        response = await call_next(request)
        return response
else:
    logger.warning("Authentication disabled - server will use fallback credentials")
```

### Phase 4: Testing OAuth Implementation

#### 4.1 Local Testing
Test OAuth flow locally before deploying:

```bash
# Set OAuth environment variables
export ENABLE_AUTH=true
export OAUTH_JWKS_URL=https://your-idp.com/.well-known/jwks.json
export OAUTH_AUDIENCE=cloudwatch-mcp-server
export OAUTH_ISSUER=https://your-idp.com

# Run server locally
cd src/cloudwatch-mcp-server
uv run server.py
```

Test with curl:
```bash
# Get OAuth token from your IdP (implementation depends on provider)
TOKEN="your-test-token"

# Test authenticated request
curl -X POST http://localhost:3334/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "get_active_alarms",
      "arguments": {"region": "us-east-1"}
    },
    "id": 1
  }'
```

#### 4.2 Integration Testing in jarvis-demo
1. Deploy OAuth-enabled configuration
2. Test login flow through jarvis-demo UI
3. Verify OAuth token is passed to MCP server
4. Verify user-specific AWS credentials are used
5. Test with multiple users to ensure isolation

#### 4.3 Monitoring and Logging
Add detailed logging for OAuth flow:
- Token validation success/failure
- User identification
- AWS credential extraction
- API calls made with user credentials

```python
logger.info(f"User {user_email} authenticated successfully")
logger.info(f"Making CloudWatch API call with user credentials")
logger.info(f"API call completed for user {user_email}")
```

### Phase 5: Production Deployment

#### 5.1 Deploy OAuth Configuration
```bash
# pragma: allowlist secret
# Create OAuth credentials secret
kubectl create secret generic oauth-credentials \
  --from-literal=client-id='production-client-id' \
  --from-literal=client-secret='production-client-secret' \
  -n jarvis-demo

# Deploy OAuth-enabled CloudWatch MCP
kubectl apply -f k8s/jarvis-demo/deployment-oauth.yaml

# Update LibreChat ConfigMap with OAuth settings
kubectl apply -f k8s/jarvis-demo/librechat-config.yaml

# Restart jarvis-api to pick up new configuration
kubectl rollout restart deployment/jarvis-api -n jarvis-demo
```

#### 5.2 Verify Deployment
```bash
# Check CloudWatch MCP logs
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=100

# Check for authentication messages
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp | grep -i "auth\|oauth\|token"

# Test health endpoint
kubectl port-forward -n jarvis-demo svc/cloudwatch-mcp 3334:3334
curl http://localhost:3334/health
```

#### 5.3 Remove Testing Configuration
Once OAuth is working:
1. Delete `deployment-no-auth.yaml` or mark as deprecated
2. Remove `refresh-cloudwatch-creds.sh` script (no longer needed)
3. Delete testing `aws-credentials` secret
4. Update documentation to reflect OAuth as primary method

## Security Considerations

### Token Security
- Store OAuth client secrets in Kubernetes secrets, never in code
- Use short-lived tokens (1 hour max)
- Implement token refresh mechanism
- Validate tokens on every request

### AWS Credential Isolation
- Each user must have separate AWS credentials
- Implement proper IAM policies for least-privilege access
- Log all API calls with user identification
- Implement rate limiting per user

### Network Security
- Use TLS for all OAuth communication
- Restrict MCP server access to jarvis-api only (NetworkPolicy)
- Use private subnets for Kubernetes cluster
- Implement Web Application Firewall (WAF) for jarvis-demo

### Audit and Compliance
- Log all authentication attempts
- Log all AWS API calls with user context
- Implement CloudTrail for AWS API auditing
- Regular security reviews of OAuth configuration

## Dependencies and Prerequisites

### Required Python Packages
Add to `pyproject.toml`:
```toml
[project]
dependencies = [
    "PyJWT[crypto]>=2.8.0",  # For JWT validation
    "cryptography>=41.0.0",   # For JWT crypto
]
```

### Infrastructure Requirements
- OAuth Identity Provider configured
- AWS IAM Identity Center integration (if applicable)
- HTTPS endpoint for jarvis-demo (required for OAuth redirect)
- DNS configuration for jarvis-demo domain

## Rollback Plan

If OAuth implementation fails:

1. **Immediate Rollback:**
   ```bash
   kubectl apply -f k8s/jarvis-demo/deployment-no-auth.yaml
   ./scripts/refresh-cloudwatch-creds.sh
   ```

2. **Restore LibreChat Configuration:**
   ```bash
   # Revert to pre-OAuth librechat.yaml
   kubectl apply -f k8s/jarvis-demo/librechat-config-no-auth.yaml
   kubectl rollout restart deployment/jarvis-api -n jarvis-demo
   ```

3. **Investigate Issues:**
   - Check CloudWatch MCP logs for authentication errors
   - Verify OAuth provider configuration
   - Test token validation separately
   - Check AWS credential extraction

## Timeline Estimate

- **Phase 1 (OAuth Provider Configuration):** 1-2 days
- **Phase 2 (LibreChat Configuration):** 1 day
- **Phase 3 (CloudWatch MCP OAuth Implementation):** 3-4 days
- **Phase 4 (Testing):** 2-3 days
- **Phase 5 (Production Deployment):** 1 day
- **Total:** 8-11 days

## Success Criteria

OAuth implementation is successful when:
- [ ] Users can log in through jarvis-demo UI with their credentials
- [ ] OAuth tokens are validated correctly
- [ ] Each user's AWS credentials are isolated and used correctly
- [ ] CloudWatch API calls are made with user-specific credentials
- [ ] All existing CloudWatch MCP tools work with OAuth
- [ ] Proper logging and monitoring in place
- [ ] Security review completed and approved
- [ ] Documentation updated
- [ ] Testing configuration removed/deprecated

## Resources and References

### AWS Documentation
- [IAM Identity Center (SSO)](https://docs.aws.amazon.com/singlesignon/latest/userguide/)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)

### OAuth and JWT
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [JSON Web Tokens (JWT)](https://jwt.io/)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)

### LibreChat Documentation
- [LibreChat MCP Integration](https://www.librechat.ai/docs/configuration/librechat_yaml/object_structure/mcp_servers)
- [LibreChat OAuth Configuration](https://www.librechat.ai/docs/configuration/authentication)

### Related Project Documentation
- [JARVIS_DEMO_DEPLOYMENT_STORY.md](./JARVIS_DEMO_DEPLOYMENT_STORY.md) - Current testing deployment
- [DEPLOYMENT_OPTIONS.md](./DEPLOYMENT_OPTIONS.md) - General deployment options
- [authentication/OAUTH_FLOW.md](./authentication/OAUTH_FLOW.md) - Detailed OAuth flow diagrams

## Support

For questions or issues during OAuth implementation:
1. Review error logs in CloudWatch MCP pod
2. Check OAuth provider documentation
3. Verify token claims using jwt.io
4. Test token validation independently
5. Contact AWS Support for IAM Identity Center issues
