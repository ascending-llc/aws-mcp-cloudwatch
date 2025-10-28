# AWS Authentication Integration Guide

This guide covers implementing OAuth authentication for the CloudWatch MCP Server with AWS account/profile integration.

## Architecture Overview

```
┌─────────┐    ①Login    ┌──────────────┐    ②JWT     ┌─────────────┐
│  User   │─────────────▶│ Auth Provider│────────────▶│  MCP Server │
└─────────┘              └──────────────┘             └─────────────┘
                                                              │
                                                         ③Exchange JWT
                                                              │
                                                              ▼
                                                       ┌─────────────┐
                                                       │  AWS STS    │
                                                       │ AssumeRole  │
                                                       └─────────────┘
                                                              │
                                                         ④AWS Creds
                                                              ▼
                                                       ┌─────────────┐
                                                       │ CloudWatch  │
                                                       │   APIs      │
                                                       └─────────────┘
```

## Option 1: AWS IAM Identity Center (Recommended)

### When to Use
- ✅ Your organization uses AWS Organizations
- ✅ You need multi-account access
- ✅ You want enterprise-grade SSO
- ✅ You already have IAM Identity Center configured

### Setup Steps

#### 1. Enable IAM Identity Center
```bash
# Via AWS Console or CLI
aws sso-admin create-instance \
  --region us-east-1

# Note the Instance ARN and Identity Store ID
```

#### 2. Create Permission Set for CloudWatch
```bash
# Create permission set with CloudWatch read permissions
aws sso-admin create-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-xxxxx \
  --name CloudWatchMCPAccess \
  --description "CloudWatch MCP Server access"

# Attach managed policy
aws sso-admin attach-managed-policy-to-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-xxxxx \
  --permission-set-arn arn:aws:sso:::permissionSet/xxxxx \
  --managed-policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess
```

#### 3. Register MCP Server as OIDC Application
```bash
# Create application in IAM Identity Center
aws sso-admin create-application \
  --instance-arn arn:aws:sso:::instance/ssoins-xxxxx \
  --name cloudwatch-mcp-server \
  --application-provider-arn arn:aws:sso::aws:applicationProvider/custom
```

#### 4. Configure Server to Validate OIDC Tokens

Create `cloudwatch_mcp_server/auth.py`:
```python
"""AWS IAM Identity Center authentication."""

import os
from typing import Optional
import jwt
import requests
from functools import lru_cache
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from loguru import logger

security = HTTPBearer()

# IAM Identity Center OIDC configuration
IDENTITY_CENTER_REGION = os.getenv('AWS_IDENTITY_CENTER_REGION', 'us-east-1')
IDENTITY_CENTER_ISSUER = os.getenv('AWS_IDENTITY_CENTER_ISSUER')

@lru_cache(maxsize=1)
def get_jwks():
    """Fetch JWKS from IAM Identity Center."""
    jwks_url = f"{IDENTITY_CENTER_ISSUER}/.well-known/jwks.json"
    response = requests.get(jwks_url)
    response.raise_for_status()
    return response.json()

async def verify_identity_center_token(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> dict:
    """Verify JWT token from IAM Identity Center."""
    token = credentials.credentials

    try:
        # Get signing keys
        jwks = get_jwks()

        # Decode and verify token
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}

        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e']
                }
                break

        if not rsa_key:
            raise HTTPException(status_code=401, detail="Invalid token: Key not found")

        # Verify token
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=['RS256'],
            audience=os.getenv('AWS_IDENTITY_CENTER_CLIENT_ID'),
            issuer=IDENTITY_CENTER_ISSUER
        )

        logger.info(f"Token verified for user: {payload.get('email')}")
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

async def get_aws_credentials_from_token(token_payload: dict) -> dict:
    """Exchange IAM Identity Center token for AWS credentials."""
    import boto3

    # The token includes the user's identity
    # Use AssumeRole or AssumeRoleWithWebIdentity
    sts_client = boto3.client('sts', region_name=IDENTITY_CENTER_REGION)

    # Get the role ARN associated with this user's permission set
    role_arn = token_payload.get('custom:role_arn')  # Custom claim with role ARN

    if not role_arn:
        raise HTTPException(status_code=403, detail="No role associated with user")

    # Assume the role
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"cloudwatch-mcp-{token_payload.get('sub')}",
        DurationSeconds=3600
    )

    return {
        'access_key_id': response['Credentials']['AccessKeyId'],
        'secret_access_key': response['Credentials']['SecretAccessKey'],
        'session_token': response['Credentials']['SessionToken'],
        'expiration': response['Credentials']['Expiration']
    }
```

#### 5. Update server.py to Use Authentication
```python
# Add to server.py
from fastapi import Depends, FastAPI
from cloudwatch_mcp_server.auth import verify_identity_center_token, get_aws_credentials_from_token

# Add middleware to verify authentication
@mcp.custom_route("/mcp", methods=["POST"])
async def authenticated_mcp_endpoint(
    request: dict,
    token_payload: dict = Depends(verify_identity_center_token)
):
    """MCP endpoint with authentication."""
    # Get AWS credentials for this user
    aws_creds = await get_aws_credentials_from_token(token_payload)

    # Store credentials in request context for tools to use
    request.state.aws_credentials = aws_creds

    # Process MCP request normally
    return await mcp.handle_request(request)
```

---

## Option 2: AWS Cognito + Identity Pools

### When to Use
- ✅ Simpler setup without AWS Organizations
- ✅ Need to support external users (not just employees)
- ✅ Want social login (Google, Facebook, etc.)
- ✅ Need custom user attributes

### Setup Steps

#### 1. Create Cognito User Pool
```bash
aws cognito-idp create-user-pool \
  --pool-name cloudwatch-mcp-users \
  --auto-verified-attributes email \
  --username-attributes email \
  --mfa-configuration OPTIONAL \
  --region us-east-1
```

#### 2. Create User Pool Client
```bash
aws cognito-idp create-user-pool-client \
  --user-pool-id us-east-1_xxxxx \
  --client-name cloudwatch-mcp-client \
  --generate-secret \
  --allowed-o-auth-flows authorization_code \
  --allowed-o-auth-scopes openid profile email \
  --callback-urls https://your-mcp-server.com/callback \
  --supported-identity-providers COGNITO
```

#### 3. Create Identity Pool
```bash
aws cognito-identity create-identity-pool \
  --identity-pool-name cloudwatch-mcp-identity \
  --allow-unauthenticated-identities false \
  --cognito-identity-providers \
    ProviderName=cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxx,ClientId=xxxxx
```

#### 4. Create IAM Role for Authenticated Users
```bash
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "us-east-1:xxxxx-identity-pool-id"
        }
      }
    }
  ]
}
EOF

aws iam create-role \
  --role-name CloudWatchMCPAuthenticatedRole \
  --assume-role-policy-document file://trust-policy.json

# Attach CloudWatch permissions
aws iam attach-role-policy \
  --role-name CloudWatchMCPAuthenticatedRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess
```

#### 5. Implementation Code

Create `cloudwatch_mcp_server/cognito_auth.py`:
```python
"""AWS Cognito authentication."""

import os
from typing import Optional
import jwt
from jwt import PyJWKClient
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from loguru import logger
import boto3

security = HTTPBearer()

# Cognito configuration
COGNITO_REGION = os.getenv('AWS_COGNITO_REGION', 'us-east-1')
COGNITO_USER_POOL_ID = os.getenv('AWS_COGNITO_USER_POOL_ID')
COGNITO_CLIENT_ID = os.getenv('AWS_COGNITO_CLIENT_ID')
COGNITO_IDENTITY_POOL_ID = os.getenv('AWS_COGNITO_IDENTITY_POOL_ID')

# JWKS URL
JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

async def verify_cognito_token(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> dict:
    """Verify JWT token from Cognito."""
    token = credentials.credentials

    try:
        # Get signing keys
        jwks_client = PyJWKClient(JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Verify token
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            audience=COGNITO_CLIENT_ID,
            issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
        )

        logger.info(f"Token verified for user: {payload.get('email')}")
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

async def get_aws_credentials_from_cognito(cognito_token: str, token_payload: dict) -> dict:
    """Exchange Cognito token for AWS credentials via Identity Pool."""
    cognito_identity = boto3.client('cognito-identity', region_name=COGNITO_REGION)

    # Get Identity ID
    identity_response = cognito_identity.get_id(
        IdentityPoolId=COGNITO_IDENTITY_POOL_ID,
        Logins={
            f'cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}': cognito_token
        }
    )

    identity_id = identity_response['IdentityId']

    # Get credentials for this identity
    credentials_response = cognito_identity.get_credentials_for_identity(
        IdentityId=identity_id,
        Logins={
            f'cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}': cognito_token
        }
    )

    creds = credentials_response['Credentials']

    return {
        'access_key_id': creds['AccessKeyId'],
        'secret_access_key': creds['SecretAccessKey'],
        'session_token': creds['SessionToken'],
        'expiration': creds['Expiration']
    }
```

---

## Option 3: Third-Party OAuth (Okta/Auth0) + AWS STS

### When to Use
- ✅ Company already uses Okta, Auth0, Azure AD, etc.
- ✅ Need to maintain existing identity provider
- ✅ Multi-cloud environment (not just AWS)

### Architecture
```
User → Okta/Auth0 → JWT → MCP validates → Exchange for AWS creds via STS AssumeRoleWithWebIdentity
```

### Setup Steps

#### 1. Configure OIDC Provider in AWS IAM
```bash
aws iam create-open-id-connect-provider \
  --url https://your-okta-domain.okta.com \
  --client-id-list your-client-id \
  --thumbprint-list <certificate-thumbprint>
```

#### 2. Create IAM Role with OIDC Trust Policy
```bash
cat > oidc-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT-ID:oidc-provider/your-okta-domain.okta.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "your-okta-domain.okta.com:aud": "your-client-id"
        }
      }
    }
  ]
}
EOF

aws iam create-role \
  --role-name CloudWatchMCPOIDCRole \
  --assume-role-policy-document file://oidc-trust-policy.json

aws iam attach-role-policy \
  --role-name CloudWatchMCPOIDCRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess
```

#### 3. Implementation
```python
"""Third-party OIDC authentication."""

import os
import boto3
from jwt import PyJWKClient
import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer

security = HTTPBearer()

OIDC_ISSUER = os.getenv('OIDC_ISSUER')  # e.g., https://your-domain.okta.com
OIDC_CLIENT_ID = os.getenv('OIDC_CLIENT_ID')
AWS_ROLE_ARN = os.getenv('AWS_CLOUDWATCH_ROLE_ARN')

async def verify_oidc_token(credentials = Security(security)) -> dict:
    """Verify OIDC token from third-party provider."""
    token = credentials.credentials

    jwks_url = f"{OIDC_ISSUER}/.well-known/jwks.json"
    jwks_client = PyJWKClient(jwks_url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    payload = jwt.decode(
        token,
        signing_key.key,
        algorithms=['RS256'],
        audience=OIDC_CLIENT_ID,
        issuer=OIDC_ISSUER
    )

    return payload

async def get_aws_credentials_from_oidc(oidc_token: str) -> dict:
    """Exchange OIDC token for AWS credentials."""
    sts_client = boto3.client('sts')

    response = sts_client.assume_role_with_web_identity(
        RoleArn=AWS_ROLE_ARN,
        RoleSessionName='cloudwatch-mcp-session',
        WebIdentityToken=oidc_token,
        DurationSeconds=3600
    )

    return {
        'access_key_id': response['Credentials']['AccessKeyId'],
        'secret_access_key': response['Credentials']['SecretAccessKey'],
        'session_token': response['Credentials']['SessionToken'],
        'expiration': response['Credentials']['Expiration']
    }
```

---

## Comparison Matrix

| Feature | IAM Identity Center | Cognito | Third-Party OIDC |
|---------|-------------------|---------|------------------|
| **Setup Complexity** | Medium | Low | Medium-High |
| **AWS Integration** | Excellent | Very Good | Good |
| **Multi-Account** | Native | Manual | Manual |
| **External Users** | Limited | Excellent | Excellent |
| **Social Login** | Via Federation | Native | Via Provider |
| **Cost** | Included with AWS | Pay per MAU | Provider cost |
| **Best For** | AWS Organizations | Simpler setups | Existing IdP |

---

## Recommended Approach

### For Your Use Case (Company Deployment):

**I recommend starting with AWS Cognito** because:

1. ✅ **Simplest to implement** - Works without AWS Organizations
2. ✅ **Cost-effective** - Free tier covers testing
3. ✅ **Good AWS integration** - Identity Pools handle credential vending
4. ✅ **Flexible** - Can add SSO federation later if needed
5. ✅ **Production-ready** - Scales automatically

### Implementation Priority:

1. **Phase 1**: Implement Cognito authentication
2. **Phase 2**: Test with temporary AWS credentials
3. **Phase 3**: If company already has Okta/Azure AD, add federation
4. **Phase 4**: If multi-account needed, migrate to IAM Identity Center

---

## Next Steps

To implement Cognito authentication:

1. **Update dependencies** in `pyproject.toml`:
   ```toml
   dependencies = [
       # ... existing deps
       "pyjwt[crypto]>=2.8.0",
       "python-jose[cryptography]>=3.3.0",
   ]
   ```

2. **Set up Cognito resources** (CloudFormation template available)

3. **Implement authentication middleware** (code provided above)

4. **Update Docker environment variables**

5. **Test authentication flow**