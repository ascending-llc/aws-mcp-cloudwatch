# IAM Identity Center Setup Guide

This guide walks you through configuring AWS IAM Identity Center (formerly AWS SSO) for the CloudWatch MCP Server.

## Prerequisites

- AWS IAM Identity Center already enabled in your AWS Organization
- AWS CLI v2 installed and configured
- Administrator access to IAM Identity Center
- The AWS account ID where CloudWatch MCP Server will run

## Overview

The setup involves 4 main steps:
1. Register MCP server as an OIDC application in IAM Identity Center
2. Create a CloudWatch access role with OIDC trust policy
3. Create/update a permission set for CloudWatch access
4. Assign users/groups to the application

---

## Step 1: Get IAM Identity Center Details

First, get your IAM Identity Center instance details:

```bash
# Get your Identity Center instance ARN and details
aws sso-admin list-instances

# Output will include:
# - InstanceArn: arn:aws:sso:::instance/ssoins-xxxxxxxxxxxx
# - IdentityStoreId: d-xxxxxxxxxx
```

**Save these values - you'll need them for subsequent commands.**

Set environment variables for convenience:

```bash
export SSO_INSTANCE_ARN="arn:aws:sso:::instance/ssoins-xxxxxxxxxxxx"
export IDENTITY_STORE_ID="d-xxxxxxxxxx"
export AWS_ACCOUNT_ID="123456789012"  # Your AWS account ID
export AWS_REGION="us-east-1"
```

---

## Step 2: Register MCP Server as OIDC Application

### Get the IAM Identity Center OIDC Issuer

```bash
# Get the OIDC issuer URL
aws sso-admin describe-instance \
  --instance-arn $SSO_INSTANCE_ARN \
  --query 'Instance.Oidc.Issuer' \
  --output text

# Example output: https://portal.sso.us-east-1.amazonaws.com/saml/assertion/xxxxx
```

**Note**: The OIDC issuer URL will be something like:
- Format: `https://YOUR-IDENTITY-CENTER-DOMAIN.awsapps.com/start`
- Or: `https://portal.sso.REGION.amazonaws.com/saml/assertion/xxxxx`

**Save this URL** - you'll need it for the `AWS_IDENTITY_CENTER_ISSUER` environment variable.

### Create Application in IAM Identity Center

Unfortunately, creating custom OIDC applications via CLI is limited. You'll need to use the AWS Console for this step:

#### Via AWS Console:

1. **Navigate to IAM Identity Center Console**:
   - Go to https://console.aws.amazon.com/singlesignon/
   - Select your IAM Identity Center instance

2. **Create Application**:
   - Click "Applications" in the left sidebar
   - Click "Add application"
   - Choose "I have an application I want to set up" → "OAuth 2.0/OIDC"

3. **Configure Application**:
   - **Application name**: `cloudwatch-mcp-server`
   - **Description**: `CloudWatch MCP Server authentication`
   - **Application start URL**: `http://your-mcp-server.com:3334` (your MCP server URL)
   - **Managed application**: No

4. **OIDC Configuration**:
   - **Grant types**:
     - ✅ Authorization code
     - ✅ Refresh token
   - **Redirect URIs**:
     - Add: `http://localhost:3334/callback` (for local testing)
     - Add: `https://your-mcp-server.com/callback` (for production)
   - **Scopes**:
     - ✅ openid
     - ✅ profile
     - ✅ email

5. **Save and Get Client ID**:
   - After creating, note the **Client ID** and **Client Secret**
   - **Save these** - you'll need them for environment variables

---

## Step 3: Create IAM Role for CloudWatch Access

### Create Trust Policy

Create a file `trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::AWS_ACCOUNT_ID:oidc-provider/YOUR-IDENTITY-CENTER-DOMAIN.awsapps.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "YOUR-IDENTITY-CENTER-DOMAIN.awsapps.com:aud": "YOUR-CLIENT-ID"
        }
      }
    }
  ]
}
```

Replace:
- `AWS_ACCOUNT_ID` with your account ID
- `YOUR-IDENTITY-CENTER-DOMAIN` with your actual domain (from issuer URL)
- `YOUR-CLIENT-ID` with the client ID from Step 2

### Create the IAM Role

```bash
# Create the role
aws iam create-role \
  --role-name CloudWatchMCPServerRole \
  --assume-role-policy-document file://trust-policy.json \
  --description "Role for CloudWatch MCP Server to access CloudWatch APIs" \
  --region $AWS_REGION

# Get the role ARN (save this!)
aws iam get-role \
  --role-name CloudWatchMCPServerRole \
  --query 'Role.Arn' \
  --output text

# Example output: arn:aws:iam::123456789012:role/CloudWatchMCPServerRole
```

### Attach CloudWatch Permissions

```bash
# Attach managed policy for CloudWatch read-only access
aws iam attach-role-policy \
  --role-name CloudWatchMCPServerRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess

# Attach managed policy for CloudWatch Logs read-only access
aws iam attach-role-policy \
  --role-name CloudWatchMCPServerRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess

# Verify policies attached
aws iam list-attached-role-policies \
  --role-name CloudWatchMCPServerRole
```

### (Optional) Create Custom Policy for Tighter Permissions

If you want more granular control:

```bash
cat > cloudwatch-mcp-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeAlarmHistory",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:GetLogEvents",
        "logs:StartQuery",
        "logs:StopQuery",
        "logs:GetQueryResults",
        "logs:DescribeQueryDefinitions",
        "logs:ListAnomalyDetectors",
        "logs:ListAnomalies"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Create custom policy
aws iam create-policy \
  --policy-name CloudWatchMCPServerPolicy \
  --policy-document file://cloudwatch-mcp-policy.json

# Attach custom policy
aws iam attach-role-policy \
  --role-name CloudWatchMCPServerRole \
  --policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/CloudWatchMCPServerPolicy
```

---

## Step 4: Assign Users/Groups to Application

Via AWS Console:

1. **Navigate to your application**:
   - IAM Identity Center Console → Applications → cloudwatch-mcp-server

2. **Assign users or groups**:
   - Click "Assign users or groups"
   - Select users/groups that should have access
   - Click "Assign users" or "Assign groups"

3. **Verify assignments**:
   - Check "Assigned users and groups" tab
   - Users should now see the app in their IAM Identity Center portal

---

## Step 5: Configure Environment Variables

Now that you have all the values, configure your MCP server environment variables:

```bash
# Required for IAM Identity Center authentication
export ENABLE_AUTH=true
export AWS_IDENTITY_CENTER_REGION=us-east-1
export AWS_IDENTITY_CENTER_ISSUER=https://YOUR-DOMAIN.awsapps.com/start
export AWS_IDENTITY_CENTER_CLIENT_ID=<client-id-from-step-2>
export AWS_CLOUDWATCH_ROLE_ARN=arn:aws:iam::123456789012:role/CloudWatchMCPServerRole

# Optional: Server configuration
export CLOUDWATCH_MCP_PORT=3334
export CLOUDWATCH_MCP_SERVER_HOST=0.0.0.0
export FASTMCP_LOG_LEVEL=INFO
```

For Docker:

```bash
# Save to .env file
cat > .env <<'EOF'
ENABLE_AUTH=true
AWS_IDENTITY_CENTER_REGION=us-east-1
AWS_IDENTITY_CENTER_ISSUER=https://YOUR-DOMAIN.awsapps.com/start
AWS_IDENTITY_CENTER_CLIENT_ID=your-client-id
AWS_CLOUDWATCH_ROLE_ARN=arn:aws:iam::123456789012:role/CloudWatchMCPServerRole
CLOUDWATCH_MCP_PORT=3334
CLOUDWATCH_MCP_SERVER_HOST=0.0.0.0
FASTMCP_LOG_LEVEL=INFO
EOF
```

---

## Testing the Setup

### 1. Test OIDC Configuration

```bash
# Verify the OIDC endpoint is accessible
curl https://YOUR-DOMAIN.awsapps.com/start/.well-known/openid-configuration

# Should return OIDC discovery document
```

### 2. Get a Test Token

You'll need to implement an OAuth flow to get a token, or use a tool like Postman:

1. Navigate to: `https://YOUR-DOMAIN.awsapps.com/start`
2. Log in with your IAM Identity Center credentials
3. Authorize the cloudwatch-mcp-server application
4. Capture the token from the redirect

### 3. Test MCP Server Authentication

```bash
# Start the server
docker run -d \
  --name cloudwatch-mcp-test \
  --env-file .env \
  -p 3334:3334 \
  cloudwatch-mcp-server:latest

# Test with token
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3334/mcp
```

---

## Troubleshooting

### "Invalid token" errors

**Check**:
- Token hasn't expired (default: 1 hour)
- Client ID matches the one in the token's `aud` claim
- Issuer URL is correct in environment variables

**Debug**:
```bash
# Decode JWT token (without validation)
echo "YOUR_TOKEN" | cut -d '.' -f 2 | base64 -d | jq .

# Check aud, iss, exp claims
```

### "AssumeRole failed" errors

**Check**:
- IAM role trust policy includes the correct OIDC provider
- Role ARN is correct in `AWS_CLOUDWATCH_ROLE_ARN`
- Token includes required claims

**Debug**:
```bash
# Test assume role manually
aws sts assume-role-with-web-identity \
  --role-arn $AWS_CLOUDWATCH_ROLE_ARN \
  --role-session-name test-session \
  --web-identity-token YOUR_TOKEN
```

### "OIDC provider not found" errors

You may need to create the OIDC provider first:

```bash
# Get the thumbprint (for root CA)
echo | openssl s_client -servername YOUR-DOMAIN.awsapps.com \
  -showcerts -connect YOUR-DOMAIN.awsapps.com:443 2>/dev/null \
  | openssl x509 -outform PEM | openssl x509 -fingerprint -noout \
  | sed 's/://g' | cut -d '=' -f 2

# Create OIDC provider
aws iam create-open-id-connect-provider \
  --url https://YOUR-DOMAIN.awsapps.com \
  --client-id-list YOUR-CLIENT-ID \
  --thumbprint-list THUMBPRINT_FROM_ABOVE
```

---

## Multi-Account Setup (Future)

When ready for multi-account access:

### 1. Create Permission Set

```bash
# Create permission set
aws sso-admin create-permission-set \
  --instance-arn $SSO_INSTANCE_ARN \
  --name CloudWatchMCPAccess \
  --description "CloudWatch MCP Server access across accounts"

# Get permission set ARN
aws sso-admin list-permission-sets \
  --instance-arn $SSO_INSTANCE_ARN
```

### 2. Assign to Multiple Accounts

```bash
# Assign to account 1
aws sso-admin create-account-assignment \
  --instance-arn $SSO_INSTANCE_ARN \
  --permission-set-arn <permission-set-arn> \
  --principal-type USER \
  --principal-id <user-id> \
  --target-type AWS_ACCOUNT \
  --target-id 111111111111

# Assign to account 2
aws sso-admin create-account-assignment \
  --instance-arn $SSO_INSTANCE_ARN \
  --permission-set-arn <permission-set-arn> \
  --principal-type USER \
  --principal-id <user-id> \
  --target-type AWS_ACCOUNT \
  --target-id 222222222222
```

### 3. Update MCP Server

The server can read the user's assigned accounts from the token and allow account switching via API parameter.

---

## Security Best Practices

1. **Token Expiration**: Tokens expire after 1 hour by default - implement refresh
2. **HTTPS Only**: Never send tokens over HTTP in production
3. **Role Session Duration**: Consider shorter durations for sensitive operations
4. **Audit Logging**: Enable CloudTrail to log AssumeRole calls
5. **Least Privilege**: Use custom IAM policy instead of managed policies when possible
6. **Rotate Secrets**: If using client secret, rotate regularly

---

## Summary

After completing this setup, you'll have:

✅ IAM Identity Center application for CloudWatch MCP Server
✅ OIDC-based authentication flow
✅ IAM role with CloudWatch permissions
✅ Users assigned and able to log in
✅ Environment variables configured

Users can now:
1. Log in via IAM Identity Center portal
2. Get an OIDC token
3. Use the token to authenticate to MCP server
4. MCP server assumes role and accesses CloudWatch

**Next**: Configure the MCP server code to use these values (see STARLETTE_AUTH_GUIDE.md)
