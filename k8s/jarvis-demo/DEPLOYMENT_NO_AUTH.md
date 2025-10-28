# CloudWatch MCP Deployment Without User Authentication

This guide shows how to deploy the CloudWatch MCP server with **authentication disabled**, using IAM Roles for Service Accounts (IRSA) for AWS access instead of user OIDC tokens.

## Use Case

Deploy this configuration when:
- You don't have permissions to create IAM Identity Center OIDC applications
- You want internal-only access without user authentication
- You're testing or in development mode
- You'll control access via Kubernetes RBAC/network policies instead

## Architecture

```
User Request → MCP Server (no auth) → AWS CloudWatch APIs
                                       ↓
                                   IRSA Role
```

**Key Points:**
- No user authentication (no OIDC tokens required)
- Server uses Kubernetes Service Account with IAM role
- IAM role provides CloudWatch access to the pod
- Access control via Kubernetes network policies

## Prerequisites

1. **EKS Cluster** with OIDC provider configured
2. **kubectl** access to cluster
3. **AWS CLI** with permissions to create IAM roles
4. **ECR** repository created (jarvis/cloudwatch_mcp_server)

## Step 1: Configure EKS OIDC Provider

Check if OIDC provider exists:

```bash
# Get OIDC provider URL
aws eks describe-cluster \
  --name ascending-s-api-cluster \
  --region us-east-1 \
  --query "cluster.identity.oidc.issuer" \
  --output text

# Example output: https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE
```

If not configured:

```bash
# Create OIDC provider (if using eksctl)
eksctl utils associate-iam-oidc-provider \
  --cluster ascending-s-api-cluster \
  --region us-east-1 \
  --approve

# Or manually via AWS console:
# EKS → Clusters → ascending-s-api-cluster → Add-ons → Configure OIDC
```

## Step 2: Create IAM Role for Service Account

### 2.1: Get OIDC Provider ID

```bash
# Extract OIDC provider ID
OIDC_PROVIDER=$(aws eks describe-cluster \
  --name ascending-s-api-cluster \
  --region us-east-1 \
  --query "cluster.identity.oidc.issuer" \
  --output text | sed -e "s/^https:\/\///")

echo $OIDC_PROVIDER
# Should output: oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE

# Get your AWS account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo $ACCOUNT_ID
```

### 2.2: Create Trust Policy

```bash
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:jarvis-demo:cloudwatch-mcp-sa",
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF
```

### 2.3: Create IAM Role

```bash
# Create the role
aws iam create-role \
  --role-name cloudwatch-mcp-eks-role \
  --assume-role-policy-document file://trust-policy.json \
  --description "IAM role for CloudWatch MCP Server running in EKS"

# Get the role ARN (save this!)
ROLE_ARN=$(aws iam get-role \
  --role-name cloudwatch-mcp-eks-role \
  --query 'Role.Arn' \
  --output text)

echo "Role ARN: $ROLE_ARN"
# Example: arn:aws:iam::123456789012:role/cloudwatch-mcp-eks-role
```

### 2.4: Attach CloudWatch Permissions

```bash
# Option 1: Use AWS managed policy (recommended)
aws iam attach-role-policy \
  --role-name cloudwatch-mcp-eks-role \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess

# Option 2: Create custom policy with least privilege
cat > cloudwatch-policy.json <<EOF
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
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "logs:StartQuery",
        "logs:StopQuery",
        "logs:GetQueryResults"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name CloudWatchMCPPolicy \
  --policy-document file://cloudwatch-policy.json

aws iam attach-role-policy \
  --role-name cloudwatch-mcp-eks-role \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/CloudWatchMCPPolicy
```

## Step 3: Update Deployment Manifest

Edit `k8s/jarvis-demo/deployment-no-auth.yaml` and replace `ACCOUNT_ID` with your actual AWS account ID:

```bash
# Get your account ID
echo $ACCOUNT_ID

# Update the ServiceAccount annotation
sed -i.bak "s/ACCOUNT_ID/${ACCOUNT_ID}/g" deployment-no-auth.yaml

# Verify the change
grep "eks.amazonaws.com/role-arn" deployment-no-auth.yaml
# Should show: eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/cloudwatch-mcp-eks-role
```

## Step 4: Build and Push Docker Image

```bash
# Build and push image using GitHub Actions
gh workflow run ci-cloudwatch.yml \
  -f region=us-east-1 \
  -f release_version=0.1.0

# Wait for build to complete, then verify
aws ecr describe-images \
  --repository-name jarvis/cloudwatch_mcp_server \
  --region us-east-1 \
  --query 'imageDetails[*].[imageTags[0],imagePushedAt]' \
  --output table
```

## Step 5: Deploy to EKS

### Option A: Using kubectl

```bash
# Deploy the no-auth configuration
kubectl apply -f deployment-no-auth.yaml

# Verify deployment
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp
kubectl get svc -n jarvis-demo cloudwatch-mcp

# Check pod logs
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=50
```

### Option B: Using GitHub Actions

Modify the deploy workflow to use the no-auth manifest:

```bash
# Update deploy-cloudwatch.yml to use deployment-no-auth.yaml
# Or manually update via kubectl after GitHub Actions deploy:

kubectl set env deploy/cloudwatch-mcp ENABLE_AUTH=false -n jarvis-demo
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

## Step 6: Verify Deployment

### Check Pod Status

```bash
# View pods
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp

# Should show:
# NAME                              READY   STATUS    RESTARTS   AGE
# cloudwatch-mcp-xxxx-yyyy          1/1     Running   0          2m
# cloudwatch-mcp-xxxx-zzzz          1/1     Running   0          2m
```

### Check Pod Logs

```bash
# View logs
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=100

# Should see:
# - "Authentication disabled" message
# - "CloudWatch Logs tools registered successfully"
# - "CloudWatch Metrics tools registered successfully"
# - "CloudWatch Alarms tools registered successfully"
# - No authentication errors
```

### Test Health Endpoint

```bash
# Port-forward to local machine
kubectl port-forward -n jarvis-demo svc/cloudwatch-mcp 3334:3334

# In another terminal, test health
curl http://localhost:3334/health

# Expected: HTTP 200 OK
```

### Test CloudWatch Access

```bash
# Test a CloudWatch tool call (no auth token needed!)
curl -X POST http://localhost:3334/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_active_alarms",
    "arguments": {
      "max_items": 5,
      "region": "us-east-1"
    }
  }'

# Should return list of alarms (or empty list if no alarms)
```

## Step 7: Verify IAM Role is Working

### Check Service Account

```bash
# Verify service account has IAM role annotation
kubectl get sa cloudwatch-mcp-sa -n jarvis-demo -o yaml

# Should show:
# annotations:
#   eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/cloudwatch-mcp-eks-role
```

### Check Pod Environment

```bash
# Get shell in pod
kubectl exec -it -n jarvis-demo $(kubectl get pod -n jarvis-demo -l app=cloudwatch-mcp -o jsonpath='{.items[0].metadata.name}') -- sh

# Inside pod, check AWS credentials are injected
env | grep AWS

# Should see:
# AWS_ROLE_ARN=arn:aws:iam::ACCOUNT_ID:role/cloudwatch-mcp-eks-role
# AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
# AWS_REGION=us-east-1

# Test AWS access
python3 -c "import boto3; print(boto3.client('cloudwatch').describe_alarms(MaxRecords=1))"

# Should return alarm data (not permission errors)
```

## How It Works

### Request Flow

1. **User makes request** to MCP server (no auth token)
2. **Middleware checks** `ENABLE_AUTH=false`, skips authentication
3. **Tool handler** calls `_get_cloudwatch_client()`
4. **Client creation** checks for `request_state` (none when auth disabled)
5. **Falls back** to environment AWS credentials
6. **Boto3 uses** IRSA credentials automatically:
   - Reads `AWS_WEB_IDENTITY_TOKEN_FILE`
   - Calls STS AssumeRoleWithWebIdentity
   - Gets temporary credentials
   - Makes CloudWatch API calls

### Code Flow (middleware.py)

```python
async def dispatch(self, request: Request, call_next):
    if not self.enable_auth:  # ENABLE_AUTH=false
        return await call_next(request)  # Skip all auth
```

### Code Flow (tools.py)

```python
def _get_logs_client(self, region: str, request_state=None):
    # request_state is None when auth disabled
    if request_state and hasattr(request_state, 'aws_credentials'):
        # Use user credentials (not called when auth disabled)
        ...

    # Fall back to environment credentials (IRSA)
    if aws_profile := os.environ.get('AWS_PROFILE'):
        # Not set in EKS
        ...
    else:
        # This path is taken - boto3 auto-discovers IRSA
        return boto3.Session(region_name=region).client('logs')
```

## Troubleshooting

### Pods Crashing

```bash
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --previous

# Common issues:
# - "AccessDenied" → IAM role missing permissions
# - "WebIdentityErr" → Service account annotation incorrect
# - "NoCredentials" → OIDC provider not configured
```

### Permission Errors

```bash
# Verify role has correct permissions
aws iam list-attached-role-policies --role-name cloudwatch-mcp-eks-role

# Test role manually
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/cloudwatch-mcp-eks-role \
  --role-session-name test

# Check trust policy
aws iam get-role --role-name cloudwatch-mcp-eks-role --query 'Role.AssumeRolePolicyDocument'
```

### Service Account Not Working

```bash
# Verify OIDC provider exists
aws iam list-open-id-connect-providers

# Verify annotation
kubectl describe sa cloudwatch-mcp-sa -n jarvis-demo

# Recreate service account if needed
kubectl delete sa cloudwatch-mcp-sa -n jarvis-demo
kubectl apply -f deployment-no-auth.yaml
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

## Security Considerations

### Access Control

Since user authentication is disabled, control access via:

1. **Kubernetes RBAC** - Limit who can access the service
2. **Network Policies** - Restrict ingress to approved pods/namespaces
3. **Service Mesh** - Use Istio/Linkerd for mTLS and authorization
4. **API Gateway** - Put behind gateway with authentication

Example NetworkPolicy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloudwatch-mcp-access
  namespace: jarvis-demo
spec:
  podSelector:
    matchLabels:
      app: cloudwatch-mcp
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: librechat  # Only LibreChat pods can access
      ports:
        - protocol: TCP
          port: 3334
```

### IAM Role Permissions

Use least privilege:

```bash
# Restrict to specific log groups
{
  "Effect": "Allow",
  "Action": ["logs:*"],
  "Resource": "arn:aws:logs:us-east-1:ACCOUNT_ID:log-group:/aws/application/*"
}

# Restrict to specific regions
{
  "Effect": "Allow",
  "Action": ["cloudwatch:*"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {"aws:RequestedRegion": "us-east-1"}
  }
}
```

## Migrating to User Authentication Later

When you get permissions to create IAM Identity Center OIDC apps:

1. **Complete IAM Identity Center setup** (IAM_IDENTITY_CENTER_SETUP.md)
2. **Add External Secrets** with OIDC config
3. **Switch to auth-enabled deployment:**

```bash
kubectl apply -f deployment.yaml  # Original with auth
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

4. **Clients must now send Bearer tokens** in Authorization header

## Summary

✅ **No user authentication required**
✅ **Uses IRSA for AWS access**
✅ **Works with existing AWS permissions**
✅ **Secure pod-to-AWS communication**
⚠️ **No per-user access control** (all requests use same IAM role)
⚠️ **Requires network policies** for access control

This configuration is ideal for internal tools where you control access at the Kubernetes level rather than per-user authentication.
