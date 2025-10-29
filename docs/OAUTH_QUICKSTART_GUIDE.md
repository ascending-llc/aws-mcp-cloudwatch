# CloudWatch MCP Server - OAuth Quickstart Guide (LibreChat MCP OAuth)

## Overview

This guide provides step-by-step instructions to enable **per-MCP OAuth authentication** in the CloudWatch MCP server, allowing users to authorize CloudWatch MCP with their own AWS credentials directly from the jarvis-demo UI.

**Current State:** ✅ Working with shared SSO credentials
**Target State:** 🎯 Per-user OAuth authorization with AWS credential selection
**Prerequisites:** CloudWatch MCP server deployed and working in jarvis-demo

## Architecture: LibreChat MCP OAuth Flow

```
┌──────────────────────────────────────────────────────────┐
│  User Already Logged into jarvis-demo                   │
└──────────────────────────────────────────────────────────┘
                         │
                         v
┌──────────────────────────────────────────────────────────┐
│  jarvis-demo UI - Available MCP Servers                  │
│  ☐ Atlassian MCP      [Connected]                       │
│  ☐ Google Workspace   [Connected]                       │
│  ☐ CloudWatch MCP     [Authorize] ← User clicks         │
└──────────────────┬───────────────────────────────────────┘
                   │
                   │ 1. OAuth popup opens
                   v
┌──────────────────────────────────────────────────────────┐
│  AWS IAM Identity Center - Account Selection            │
│  ○ saas (897729109735)                                  │
│  ○ ascops (595312265488)                                │
│  [Authorize]  ← User selects account and authorizes     │
└──────────────────┬───────────────────────────────────────┘
                   │
                   │ 2. LibreChat receives OAuth token
                   │    with AWS credentials
                   v
┌──────────────────────────────────────────────────────────┐
│  LibreChat (jarvis-api)                                  │
│  - Stores OAuth token for user + CloudWatch MCP         │
│  - Manages token refresh                                 │
│  - Sends Authorization: Bearer <token> to MCP server    │
└──────────────────┬───────────────────────────────────────┘
                   │
                   │ 3. Every MCP request includes token
                   v
┌──────────────────────────────────────────────────────────┐
│  CloudWatch MCP Server                                   │
│  [Starlette Middleware]                                  │
│  - Validates JWT token                                   │
│  - Extracts AWS credentials from token                   │
│  - Uses user's credentials for CloudWatch API            │
└──────────────────────────────────────────────────────────┘
                   │
                   │ 4. Access CloudWatch with user creds
                   v
┌──────────────────────────────────────────────────────────┐
│  AWS CloudWatch API                                      │
│  (Using user's selected account credentials)             │
└──────────────────────────────────────────────────────────┘
```

## Key Differences from Standard OAuth

| Standard OAuth (App-Level) | LibreChat MCP OAuth (Per-MCP) |
|----------------------------|-------------------------------|
| Login to access entire app | Already logged into jarvis-demo |
| One OAuth flow for all features | Separate OAuth per MCP server |
| Tokens managed by app auth | Tokens managed by LibreChat per MCP |
| Single redirect URI | MCP-specific callback URI |
| Can't switch accounts easily | Can disconnect/reconnect with different account |

## Phase 1: Understand the Current Authentication Flow

### Current Setup (No Auth)
**File:** `src/cloudwatch-mcp-server/cloudwatch_mcp_server/cloudwatch_alarms/tools.py:46-80`

```python
def _get_cloudwatch_client(self, region: str, request_state=None):
    """Create a CloudWatch client for the specified region."""
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
            return boto3.Session(profile_name=aws_profile, region_name=region).client(
                'cloudwatch', config=config
            )
        else:
            return boto3.Session(region_name=region).client('cloudwatch', config=config)
```

**Key Insight:** The code already supports `request_state.aws_credentials`! We just need to populate it via OAuth middleware.

## Phase 2: Choose OAuth Provider

### Recommended: AWS IAM Identity Center (SSO)

**Why?**
- Native AWS integration
- Can embed AWS credentials in OIDC tokens
- Users already authenticate with AWS SSO
- Simplest path for CloudWatch access

**Alternative:** If your organization uses a different IdP (Okta, Azure AD), you'll need to set up AssumeRole flow separately.

### Decision Point: Do you use AWS IAM Identity Center?

**✅ Yes (Recommended path):**
- Proceed with Step 3A: Configure IAM Identity Center

**❌ No (Alternative IdPs):**
- Proceed with Step 3B: Configure External IdP + AssumeRole

---

## Phase 3A: Configure AWS IAM Identity Center (Recommended)

### Step 1: Create Custom OIDC Application

1. **Navigate to IAM Identity Center Console**
   ```
   https://console.aws.amazon.com/singlesignon/home
   ```

2. **Create Application**
   - Go to: Applications → Add application → Custom SAML 2.0 / OIDC application
   - Choose: **Custom OIDC application**
   - Name: `Jarvis Demo - CloudWatch MCP`

3. **Configure Application**
   - **Application start URL:** `https://jarvis-demo.ascendingdc.com`
   - **Redirect URI (IMPORTANT - LibreChat MCP OAuth callback):**
     ```
     https://jarvis-demo.ascendingdc.com/api/mcp/oauth/callback/cloudwatch
     ```
     **Note:** This is LibreChat's MCP-specific OAuth callback, NOT `/oauth/callback`

   - **Add for local testing:**
     ```
     http://localhost:3080/api/mcp/oauth/callback/cloudwatch
     ```

   - **Grant types:** Authorization code, Refresh token
   - **Scopes:**
     - `openid` (required)
     - `profile` (required)
     - `email` (required)

4. **Record Application Details**
   Save these values (you'll need them later):
   ```bash
   # Copy these from the application settings
   CLIENT_ID="your-application-client-id"
   CLIENT_SECRET="your-application-client-secret"
   ISSUER_URL="https://your-identity-center.awsapps.com/oidc"
   JWKS_URL="https://your-identity-center.awsapps.com/oidc/.well-known/jwks.json"
   TOKEN_ENDPOINT="https://your-identity-center.awsapps.com/oidc/token"
   AUTHORIZE_ENDPOINT="https://your-identity-center.awsapps.com/oidc/authorize"
   ```

### Step 2: Configure Custom Attribute Mappings

To embed AWS credentials in the OIDC token:

1. **In IAM Identity Center Console:**
   - Go to your application → Attribute mappings
   - Add custom attributes:

   | User attribute in Identity Center | Application attribute name | Format |
   |-----------------------------------|----------------------------|--------|
   | `${session:access_key_id}` | `aws_access_key_id` | string |
   | `${session:secret_access_key}` | `aws_secret_access_key` | string |
   | `${session:session_token}` | `aws_session_token` | string |
   | `${user:email}` | `email` | string |
   | `${user:name}` | `name` | string |

2. **Note:** This requires AWS Identity Center to issue temporary credentials for users. Ensure users have proper permission sets assigned.

### Step 3: Assign Users/Groups

1. Go to application → Assigned users/groups
2. Assign users or groups that should have access
3. Select appropriate permission set (CloudWatch read access minimum)

---

## Phase 4: Implement OAuth Authentication in CloudWatch MCP Server

### Step 1: Add Required Dependencies

**File:** `src/cloudwatch-mcp-server/pyproject.toml`

```toml
[project]
dependencies = [
    # ... existing dependencies ...
    "PyJWT[crypto]>=2.8.0",  # JWT validation
    "cryptography>=41.0.0",   # Crypto for JWT
    "httpx>=0.24.0",          # HTTP client for JWKS
]
```

Install dependencies:
```bash
cd src/cloudwatch-mcp-server
uv sync
```

### Step 2: Create Authentication Module

**File:** `src/cloudwatch-mcp-server/cloudwatch_mcp_server/auth.py` (new file)

```python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OAuth authentication and authorization for CloudWatch MCP Server."""

import os
import jwt
import httpx
from typing import Dict, Optional
from loguru import logger
from datetime import datetime, timedelta
from jwt import PyJWKClient


class OAuthValidator:
    """Validates OAuth tokens and extracts AWS credentials."""

    def __init__(self):
        """Initialize OAuth validator with configuration from environment."""
        self.jwks_url = os.environ.get('OAUTH_JWKS_URL')
        self.audience = os.environ.get('OAUTH_AUDIENCE', 'cloudwatch-mcp-server')
        self.issuer = os.environ.get('OAUTH_ISSUER')
        self.enabled = os.environ.get('ENABLE_AUTH', 'false').lower() == 'true'

        if self.enabled:
            if not all([self.jwks_url, self.issuer]):
                raise ValueError(
                    "OAuth authentication enabled but missing required config: "
                    "OAUTH_JWKS_URL and OAUTH_ISSUER must be set"
                )

            # Initialize JWKS client for token validation
            self.jwks_client = PyJWKClient(self.jwks_url, cache_keys=True)
            logger.info(f"OAuth validator initialized - Issuer: {self.issuer}")
        else:
            logger.warning("OAuth authentication is DISABLED")
            self.jwks_client = None

    def validate_token(self, token: str) -> Dict:
        """
        Validate OAuth token and extract claims.

        Args:
            token: Bearer token from Authorization header

        Returns:
            Dict containing validated token claims including AWS credentials

        Raises:
            Exception: If token is invalid or expired
        """
        if not self.enabled:
            raise ValueError("Authentication is disabled")

        try:
            # Get signing key from JWKS endpoint
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and validate token
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                }
            )

            logger.info(f"Token validated successfully for user: {claims.get('email', 'unknown')}")
            logger.debug(f"Token claims: {list(claims.keys())}")

            return claims

        except jwt.ExpiredSignatureError:
            logger.error("Token has expired")
            raise ValueError("Token has expired")
        except jwt.InvalidAudienceError:
            logger.error(f"Invalid token audience - expected: {self.audience}")
            raise ValueError("Invalid token audience")
        except jwt.InvalidIssuerError:
            logger.error(f"Invalid token issuer - expected: {self.issuer}")
            raise ValueError("Invalid token issuer")
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {str(e)}")
            raise ValueError(f"Invalid token: {str(e)}")
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            raise

    def extract_aws_credentials(self, claims: Dict) -> Dict:
        """
        Extract AWS credentials from validated token claims.

        For IAM Identity Center tokens, expects these custom claims:
        - aws_access_key_id
        - aws_secret_access_key
        - aws_session_token

        Args:
            claims: Validated JWT claims

        Returns:
            Dict with keys: access_key_id, secret_access_key, session_token

        Raises:
            ValueError: If AWS credentials are missing from token
        """
        # Extract AWS credentials from custom claims
        aws_creds = {
            'access_key_id': claims.get('aws_access_key_id'),
            'secret_access_key': claims.get('aws_secret_access_key'),
            'session_token': claims.get('aws_session_token'),
        }

        # Validate all credentials are present
        missing = [k for k, v in aws_creds.items() if not v]
        if missing:
            logger.error(f"Token missing AWS credentials: {missing}")
            logger.debug(f"Available claims: {list(claims.keys())}")
            raise ValueError(
                f"Token does not contain required AWS credentials: {', '.join(missing)}"
            )

        logger.info("AWS credentials extracted from token successfully")
        return aws_creds

    def extract_user_info(self, claims: Dict) -> Dict:
        """
        Extract user information from token claims.

        Args:
            claims: Validated JWT claims

        Returns:
            Dict containing user_email, user_name, user_id
        """
        return {
            'user_email': claims.get('email', 'unknown'),
            'user_name': claims.get('name', claims.get('preferred_username', 'unknown')),
            'user_id': claims.get('sub', 'unknown'),
        }


class RequestState:
    """Container for authenticated request state."""

    def __init__(self, user_email: str, user_name: str, user_id: str, aws_credentials: Dict):
        self.user_email = user_email
        self.user_name = user_name
        self.user_id = user_id
        self.aws_credentials = aws_credentials


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """
    Extract Bearer token from Authorization header.

    Args:
        authorization_header: Authorization header value

    Returns:
        Token string or None if not found/invalid
    """
    if not authorization_header:
        return None

    if not authorization_header.startswith('Bearer '):
        logger.warning(f"Invalid authorization header format: {authorization_header[:20]}...")
        return None

    return authorization_header[7:]  # Remove 'Bearer ' prefix
```

### Step 3: Create Starlette Middleware for FastMCP

**File:** `src/cloudwatch-mcp-server/cloudwatch_mcp_server/middleware.py` (new file)

```python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Starlette middleware for OAuth authentication in CloudWatch MCP Server."""

import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from loguru import logger
from cloudwatch_mcp_server.auth import (
    OAuthValidator,
    RequestState,
    extract_bearer_token
)


class OAuthMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware to validate OAuth tokens and attach credentials to requests.

    This middleware:
    1. Extracts Bearer token from Authorization header
    2. Validates JWT token against JWKS endpoint
    3. Extracts AWS credentials from token claims
    4. Attaches credentials to request.state for tools to use
    """

    def __init__(self, app, validator: OAuthValidator):
        """
        Initialize OAuth middleware.

        Args:
            app: Starlette/FastAPI application
            validator: Configured OAuthValidator instance
        """
        super().__init__(app)
        self.validator = validator
        self.enabled = validator.enabled

        if self.enabled:
            logger.info("OAuth middleware initialized and ENABLED")
        else:
            logger.warning("OAuth middleware initialized but DISABLED")

    async def dispatch(self, request: Request, call_next):
        """
        Process each request through OAuth validation.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain

        Returns:
            Response from downstream handler or error response
        """
        # Skip authentication if disabled
        if not self.enabled:
            logger.debug(f"Auth disabled - processing request: {request.url.path}")
            return await call_next(request)

        # Skip authentication for health/status endpoints
        if request.url.path in ['/health', '/status', '/']:
            return await call_next(request)

        # Extract token from Authorization header
        auth_header = request.headers.get('authorization')
        token = extract_bearer_token(auth_header)

        if not token:
            logger.warning(f"Missing or invalid authorization header for {request.url.path}")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Missing or invalid Authorization header. Expected: 'Bearer <token>'"
                }
            )

        try:
            # Validate token and extract claims
            claims = self.validator.validate_token(token)

            # Extract AWS credentials
            aws_credentials = self.validator.extract_aws_credentials(claims)

            # Extract user info
            user_info = self.validator.extract_user_info(claims)

            # Create request state with user credentials
            request.state.request_state = RequestState(
                user_email=user_info['user_email'],
                user_name=user_info['user_name'],
                user_id=user_info['user_id'],
                aws_credentials=aws_credentials
            )

            logger.info(
                f"Request authenticated - User: {user_info['user_email']}, "
                f"Path: {request.url.path}"
            )

            # Continue to next handler with authenticated state
            response = await call_next(request)
            return response

        except ValueError as e:
            logger.error(f"Authentication error: {str(e)}")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": str(e)
                }
            )
        except Exception as e:
            logger.error(f"Unexpected authentication error: {str(e)}", exc_info=True)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_server_error",
                    "message": "Authentication system error"
                }
            )
```

### Step 4: Update Server to Use Middleware

**File:** `src/cloudwatch-mcp-server/cloudwatch_mcp_server/server.py`

Find the section where FastMCP is initialized and add the middleware:

```python
import os
from mcp.server.fastmcp import FastMCP
from loguru import logger
from cloudwatch_mcp_server import MCP_SERVER_VERSION
from cloudwatch_mcp_server.auth import OAuthValidator
from cloudwatch_mcp_server.middleware import OAuthMiddleware

# ... existing imports ...

def main():
    """Main entry point for CloudWatch MCP server."""

    # Initialize FastMCP
    mcp = FastMCP(
        name='cloudwatch-mcp-server',
        version=MCP_SERVER_VERSION,
        dependencies=['boto3', 'botocore', 'PyJWT', 'cryptography'],
    )

    # Initialize OAuth validator
    oauth_validator = OAuthValidator()

    # Add OAuth middleware to the underlying Starlette app
    if oauth_validator.enabled:
        logger.info("Adding OAuth middleware to application")
        # FastMCP uses Starlette under the hood - access via mcp.app
        mcp.app.add_middleware(OAuthMiddleware, validator=oauth_validator)
    else:
        logger.warning("OAuth authentication is DISABLED - using fallback credentials")

    # Register tools (existing code)
    from cloudwatch_mcp_server.cloudwatch_alarms.tools import CloudWatchAlarmsTools
    from cloudwatch_mcp_server.cloudwatch_logs.tools import CloudWatchLogsTools
    from cloudwatch_mcp_server.cloudwatch_metrics.tools import CloudWatchMetricsTools

    alarms_tools = CloudWatchAlarmsTools()
    logs_tools = CloudWatchLogsTools()
    metrics_tools = CloudWatchMetricsTools()

    alarms_tools.register(mcp)
    logs_tools.register(mcp)
    metrics_tools.register(mcp)

    # Run server
    mcp.run()


if __name__ == '__main__':
    main()
```

### Step 5: Update Tool Methods to Access Request State

The tool methods already support `request_state` (see Phase 1), but we need to ensure the MCP Context passes it through. Update tool signatures:

**File:** `src/cloudwatch-mcp-server/cloudwatch_mcp_server/cloudwatch_alarms/tools.py`

```python
async def get_active_alarms(
    self,
    ctx: Context,
    max_items: int = 50,
    region: str = 'us-east-1',
) -> ActiveAlarmsResponse:
    """Get currently active CloudWatch alarms."""
    try:
        # Access authenticated request state from context
        # FastMCP will automatically populate this from request.state
        request_state = getattr(ctx, 'request_state', None)

        if request_state:
            logger.info(f"Processing request for user: {request_state.user_email}")
        else:
            logger.warning("No request state found - using fallback credentials")

        # Create CloudWatch client with user credentials
        cw = self._get_cloudwatch_client(region, request_state)

        # ... rest of implementation ...
```

**Repeat this pattern for all tool methods** in:
- `cloudwatch_logs/tools.py`
- `cloudwatch_metrics/tools.py`

---

## Phase 5: Update Deployment Configuration

### Step 1: Create OAuth-Enabled Deployment

**File:** `k8s/jarvis-demo/deployment-oauth.yaml` (new file, copy from deployment-no-auth.yaml)

```yaml
---
# CloudWatch MCP Server Deployment with OAuth Authentication
# Uses OIDC tokens from LibreChat for user authentication
# Per-user AWS credentials extracted from JWT tokens

apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudwatch-mcp
  namespace: jarvis-demo
  labels:
    app: cloudwatch-mcp
    component: mcp-server
    service: cloudwatch
    auth-mode: oauth
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cloudwatch-mcp
  template:
    metadata:
      labels:
        app: cloudwatch-mcp
        component: mcp-server
        service: cloudwatch
        auth-mode: oauth
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: cloudwatch-mcp
          image: 897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server:latest
          imagePullPolicy: Always
          ports:
            - name: http
              containerPort: 3334
              protocol: TCP
          env:
            # OAuth Authentication ENABLED
            - name: ENABLE_AUTH
              value: "true"

            # OAuth Configuration
            - name: OAUTH_JWKS_URL
              value: "https://your-identity-center.awsapps.com/oidc/.well-known/jwks.json"
            - name: OAUTH_ISSUER
              value: "https://your-identity-center.awsapps.com/oidc"
            - name: OAUTH_AUDIENCE
              value: "cloudwatch-mcp-server"

            # CloudWatch Configuration
            - name: AWS_REGION
              value: "us-east-1"
            - name: CLOUDWATCH_MCP_SERVER_HOST
              value: "0.0.0.0"
            - name: CLOUDWATCH_MCP_PORT
              value: "3334"

            # Logging
            - name: FASTMCP_LOG_LEVEL
              value: "INFO"

            # Set HOME for boto3 (still needed for SDK)
            - name: HOME
              value: "/home/app"

          resources:
            limits:
              cpu: 1000m
              memory: 1Gi
            requests:
              cpu: 250m
              memory: 512Mi

          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: false

---
apiVersion: v1
kind: Service
metadata:
  name: cloudwatch-mcp
  namespace: jarvis-demo
  labels:
    app: cloudwatch-mcp
    component: mcp-server
    service: cloudwatch
spec:
  type: ClusterIP
  ports:
    - port: 3334
      targetPort: 3334
      protocol: TCP
      name: http
  selector:
    app: cloudwatch-mcp
```

### Step 2: Update LibreChat Configuration

**File:** Update the ConfigMap `jarvis-demo/librechat-config` with OAuth settings:

```yaml
mcpServers:
  cloudwatch:
    type: streamable-http
    url: http://cloudwatch-mcp:3334/mcp
    timeout: 120000

    # LibreChat MCP OAuth Configuration
    oauth:
      # OAuth client credentials from IAM Identity Center
      clientId: "${CLOUDWATCH_OAUTH_CLIENT_ID}"
      clientSecret: "${CLOUDWATCH_OAUTH_CLIENT_SECRET}"

      # IAM Identity Center OAuth endpoints
      authorizationUrl: "https://ascending.awsapps.com/start/oidc/authorize"
      tokenUrl: "https://ascending.awsapps.com/start/oidc/token"

      # Required scopes
      scopes:
        - openid
        - profile
        - email

      # LibreChat's MCP OAuth callback (automatically configured)
      # callbackUrl: "https://jarvis-demo.ascendingdc.com/api/mcp/oauth/callback/cloudwatch"
      # Note: LibreChat automatically constructs this, no need to specify

    serverInstructions: |
      # CloudWatch MCP Server Instructions

      You have access to AWS CloudWatch through this MCP server connection for monitoring, logging, and alarm management.

      **IMPORTANT:** You must authorize this MCP server to access your AWS account before use.
      Click the "Authorize" button on the CloudWatch MCP bubble to connect with your AWS credentials.

      ## Available Capabilities:
      - **CloudWatch Logs**: Query and analyze logs using CloudWatch Logs Insights
      - **CloudWatch Metrics**: Retrieve and analyze metrics data
      - **CloudWatch Alarms**: Monitor active alarms and alarm history

      ## Usage Guidelines:
      - All CloudWatch operations use YOUR AWS credentials from the account you selected
      - You can only access resources you have permission to view
      - Always specify the AWS region when querying (defaults to us-east-1 if not specified)
      - You can disconnect and reconnect with a different AWS account at any time
```

**Configure OAuth Environment Variables:**

In the jarvis-api deployment, add these environment variables (from IAM Identity Center app):

```yaml
env:
  - name: CLOUDWATCH_OAUTH_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: cloudwatch-oauth-credentials
        key: client-id
  - name: CLOUDWATCH_OAUTH_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: cloudwatch-oauth-credentials
        key: client-secret
```

**Create the secret:**

```bash
kubectl create secret generic cloudwatch-oauth-credentials \
  --from-literal=client-id='your-iam-identity-center-client-id' \
  --from-literal=client-secret='your-iam-identity-center-client-secret' \
  -n jarvis-demo
```

---

## Phase 6: Testing OAuth Implementation

### Local Testing

1. **Set environment variables:**
```bash
export ENABLE_AUTH=true
export OAUTH_JWKS_URL=https://your-identity-center.awsapps.com/oidc/.well-known/jwks.json
export OAUTH_ISSUER=https://your-identity-center.awsapps.com/oidc
export OAUTH_AUDIENCE=cloudwatch-mcp-server
export FASTMCP_LOG_LEVEL=DEBUG
```

2. **Run server locally:**
```bash
cd src/cloudwatch-mcp-server
uv run server.py
```

3. **Test with curl:**
```bash
# Get a test token from your OAuth provider
# (implementation varies by provider)
TOKEN="your-test-jwt-token"

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

### Expected Response (Success)
```json
{
  "jsonrpc": "2.0",
  "result": {
    "region": "us-east-1",
    "active_alarms_count": 5,
    "metric_alarms": [...],
    "composite_alarms": [...]
  },
  "id": 1
}
```

### Expected Response (Auth Failure)
```json
{
  "error": "unauthorized",
  "message": "Token has expired"
}
```

---

## Phase 7: Deploy to jarvis-demo

### Step 1: Build and Push OAuth-Enabled Image

```bash
# Commit auth changes
git add src/cloudwatch-mcp-server/cloudwatch_mcp_server/auth.py
git add src/cloudwatch-mcp-server/cloudwatch_mcp_server/middleware.py
git add src/cloudwatch-mcp-server/cloudwatch_mcp_server/server.py
git add src/cloudwatch-mcp-server/pyproject.toml
git add k8s/jarvis-demo/deployment-oauth.yaml

git commit -m "feat(auth): implement OAuth authentication with Starlette middleware

- Add OAuth token validation with PyJWT
- Implement Starlette middleware for token extraction
- Extract AWS credentials from JWT claims
- Update server.py to use OAuth middleware
- Add OAuth-enabled deployment configuration

Supports AWS IAM Identity Center OIDC tokens"

git push origin main
```

### Step 2: Trigger CI/CD Build

The GitHub Actions workflow will automatically build and push the new image.

### Step 3: Deploy OAuth Configuration

```bash
# Deploy OAuth-enabled CloudWatch MCP
kubectl apply -f k8s/jarvis-demo/deployment-oauth.yaml

# Wait for rollout
kubectl rollout status deployment/cloudwatch-mcp -n jarvis-demo
```

### Step 4: Update LibreChat ConfigMap

```bash
# Update the ConfigMap with OAuth settings
kubectl edit configmap librechat-config -n jarvis-demo

# Restart jarvis-api to pick up new config
kubectl rollout restart deployment/jarvis-api -n jarvis-demo
```

### Step 5: Verify Deployment

```bash
# Check pod logs
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=100

# Look for OAuth initialization messages
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp | grep -i "oauth\|auth\|middleware"
```

Expected log output:
```
INFO: OAuth validator initialized - Issuer: https://your-identity-center.awsapps.com/oidc
INFO: OAuth middleware initialized and ENABLED
INFO: Adding OAuth middleware to application
INFO: Starting MCP server 'cloudwatch-mcp-server' with transport 'streamable-http'
```

---

## Troubleshooting

### Issue: "OAUTH_JWKS_URL must be set"

**Cause:** Environment variables not configured
**Fix:** Ensure `deployment-oauth.yaml` has correct OAuth URLs

### Issue: "Invalid token issuer"

**Cause:** Token issuer doesn't match `OAUTH_ISSUER`
**Fix:** Verify issuer in JWT token matches deployment config

### Issue: "Token does not contain required AWS credentials"

**Cause:** IAM Identity Center not configured to include credentials in token
**Fix:** Check attribute mappings in Step 3A.2

### Issue: "Missing or invalid Authorization header"

**Cause:** LibreChat not sending token to MCP server
**Fix:** Verify LibreChat ConfigMap has correct auth configuration

---

## Rollback Plan

If OAuth implementation fails:

```bash
# Revert to no-auth deployment
kubectl apply -f k8s/jarvis-demo/deployment-no-auth.yaml

# Refresh credentials
./scripts/refresh-cloudwatch-creds.sh

# Verify working
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=50
```

---

## Next Steps After OAuth Works

1. **Remove Testing Configuration**
   - Delete `deployment-no-auth.yaml`
   - Remove `refresh-cloudwatch-creds.sh` script
   - Delete `aws-credentials` secret

2. **Add Monitoring**
   - Track authentication failures
   - Monitor token validation latency
   - Alert on high auth error rates

3. **Security Hardening**
   - Implement rate limiting per user
   - Add request logging with user context
   - Set up CloudTrail for AWS API auditing

4. **Documentation**
   - Update README with OAuth setup instructions
   - Document user onboarding process
   - Create troubleshooting runbook

---

## Summary: LibreChat MCP OAuth Model

**What You'll Have After This:**
- ✅ Per-MCP OAuth authorization (user clicks "Authorize" on CloudWatch MCP bubble)
- ✅ Per-user AWS credential selection (user chooses saas or ascops account)
- ✅ LibreChat-managed token storage and refresh
- ✅ CloudWatch MCP validates tokens via Starlette middleware
- ✅ Secure, isolated access to CloudWatch APIs per user

**User Experience:**
1. User already logged into jarvis-demo (existing auth)
2. CloudWatch MCP shows "[Authorize]" button
3. User clicks → OAuth popup to AWS IAM Identity Center
4. User selects AWS account (saas/ascops) → authorizes
5. Returns to jarvis-demo → CloudWatch MCP now "[Connected]"
6. User can use CloudWatch tools with their selected account credentials

**What Makes This Different:**
- ✅ **No global jarvis-demo OAuth change** - existing authentication stays the same
- ✅ **Independent per-MCP authorization** - each MCP server has separate OAuth
- ✅ **LibreChat handles OAuth complexity** - token management, refresh, storage
- ✅ **CloudWatch MCP just validates tokens** - simpler server implementation
- ✅ **User can switch accounts** - disconnect/reconnect with different AWS account

**Key Files Created:**
- `src/cloudwatch-mcp-server/cloudwatch_mcp_server/auth.py` - JWT validation
- `src/cloudwatch-mcp-server/cloudwatch_mcp_server/middleware.py` - Starlette middleware
- `k8s/jarvis-demo/deployment-oauth.yaml` - OAuth-enabled deployment
- IAM Identity Center app with redirect: `https://jarvis-demo.ascendingdc.com/api/mcp/oauth/callback/cloudwatch`

**Estimated Time:** 2-3 days (with IAM Identity Center already configured)

**Critical Configuration Points:**
- ✅ **Redirect URI:** `https://jarvis-demo.ascendingdc.com/api/mcp/oauth/callback/cloudwatch` (LibreChat MCP callback)
- ✅ **Custom attribute mappings:** Embed AWS credentials in JWT (customer managed app required)
- ✅ **LibreChat oauth config:** clientId, clientSecret, authorizationUrl, tokenUrl
- ✅ **CloudWatch MCP OAuth validation:** OAUTH_JWKS_URL, OAUTH_ISSUER

**Resources:**
- [Main OAuth Implementation Guide](./OAUTH_IMPLEMENTATION_NEXT_STEPS.md) - Comprehensive strategic guide
- [Deployment Story](./JARVIS_DEMO_DEPLOYMENT_STORY.md) - Current deployment journey
- [LibreChat MCP OAuth Docs](https://www.librechat.ai/docs/configuration/librechat_yaml/mcp/oauth)
- [Starlette Middleware Docs](https://www.starlette.io/middleware/)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)
