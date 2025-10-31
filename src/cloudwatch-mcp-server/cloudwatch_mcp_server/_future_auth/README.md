# Future Authentication Components

This directory contains authentication middleware implementations that are **not currently used** in production but preserved for future use.

## Current Status

CloudWatch MCP Server currently uses **IRSA (IAM Roles for Service Accounts)** for authentication in EKS, which provides credential-free AWS access at the pod level. Per-user authentication is not implemented.

## Contents

### middleware.py

Contains multiple authentication middleware implementations:

1. **BrowserCredentialsMiddleware** - Accepts temporary AWS credentials via browser/client
2. **CognitoAuthMiddleware** - AWS Cognito user pool authentication
3. **IAMIdentityCenterMiddleware** - IAM Identity Center OIDC token validation
4. **OIDCMiddleware** - Generic OIDC provider support (Okta, Auth0, etc.)

## When to Use

These middleware components may be useful if/when implementing:
- Per-user authentication instead of service-level IRSA
- OAuth/OIDC flows for individual user credentials
- Multi-tenant scenarios requiring user-scoped AWS access

## Current Production Config

```yaml
# Production uses IRSA - no per-user auth
serviceAccount:
  name: cloudwatch-mcp-service-account
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::897729109735:role/CloudWatchMCPServerRole"

env:
  ENABLE_AUTH: "false"  # Middleware disabled
```

## Integration

`server.py` already has defensive imports that handle missing middleware gracefully:

```python
try:
    from cloudwatch_mcp_server.middleware import BrowserCredentialsMiddleware
except ImportError:
    BrowserCredentialsMiddleware = None
```

To re-enable, simply move `middleware.py` back to parent directory and set `ENABLE_AUTH=true`.
