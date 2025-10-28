# CloudWatch MCP - Quick Testing Setup

Deploy CloudWatch MCP for testing using **your existing AWS user credentials** (no IAM role creation needed).

## Your Situation

✅ You have an existing AWS user with CloudWatch read-only permissions
✅ No need to create new IAM users or roles
✅ OIDC provider exists (on separate company account)
✅ Just want to test the MCP server quickly

## Quick Deployment (5 minutes)

### Step 1: Create AWS Credentials Secret

**Option A: Using AWS CLI Profile** (Recommended)

```bash
# If you have ~/.aws/credentials file with your profile:
kubectl create secret generic aws-credentials \
  --from-file=credentials=$HOME/.aws/credentials \
  --from-file=config=$HOME/.aws/config \
  -n jarvis-demo

# Verify
kubectl get secret aws-credentials -n jarvis-demo
```

**Option B: Using Access Keys Directly**

```bash
# Get your access keys (if not already available)
# From AWS Console: IAM → Users → Security Credentials → Access Keys

# Create secret with access keys
kubectl create secret generic aws-credentials \
  --from-literal=access-key-id=YOUR_ACCESS_KEY_ID \
  --from-literal=secret-access-key=YOUR_SECRET_ACCESS_KEY \
  -n jarvis-demo

# If using temporary credentials (SSO), also add session token:
kubectl create secret generic aws-credentials \
  --from-literal=access-key-id=YOUR_ACCESS_KEY_ID \
  --from-literal=secret-access-key=YOUR_SECRET_ACCESS_KEY \
  --from-literal=session-token=YOUR_SESSION_TOKEN \
  -n jarvis-demo
```

**If using Option B**, uncomment the access key env vars in `deployment-no-auth.yaml`:

```yaml
# Uncomment these lines (around line 49-64):
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: aws-credentials
      key: access-key-id
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: aws-credentials
      key: secret-access-key
# - name: AWS_SESSION_TOKEN  # Only if using temporary credentials
#   valueFrom:
#     secretKeyRef:
#       name: aws-credentials
#       key: session-token
```

And comment out the AWS_PROFILE line:
```yaml
# - name: AWS_PROFILE
#   value: "default"
```

### Step 2: Build Docker Image

```bash
# Trigger GitHub Actions build
gh workflow run ci-cloudwatch.yml -f region=us-east-1

# Or build locally if you prefer:
cd src/cloudwatch-mcp-server
docker build -t 897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server:latest .
docker push 897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server:latest
```

### Step 3: Deploy to EKS

```bash
# Deploy
kubectl apply -f k8s/jarvis-demo/deployment-no-auth.yaml

# Check status
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp

# View logs
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=50
```

### Step 4: Test It

```bash
# Port forward
kubectl port-forward -n jarvis-demo svc/cloudwatch-mcp 3334:3334

# In another terminal:

# Test health
curl http://localhost:3334/health

# Test CloudWatch access (no auth token needed!)
curl -X POST http://localhost:3334/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_active_alarms",
    "arguments": {
      "region": "us-east-1",
      "max_items": 5
    }
  }'

# Test log groups
curl -X POST http://localhost:3334/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "describe_log_groups",
    "arguments": {
      "region": "us-east-1",
      "max_items": 10
    }
  }'
```

## Credential Options Explained

### Option 1: AWS Profile (Recommended for Testing)

**How it works:**
- Mounts your `~/.aws/credentials` and `~/.aws/config` into pod
- Pod uses `AWS_PROFILE=default` environment variable
- Boto3 reads credentials from mounted files

**Pros:**
- Easy to set up if you already use AWS CLI
- No need to extract access keys
- Works with named profiles

**Cons:**
- Credentials stored in pod (okay for testing)

### Option 2: Access Keys as Environment Variables

**How it works:**
- Store access keys in Kubernetes secret
- Inject as environment variables
- Boto3 reads from environment

**Pros:**
- More Kubernetes-native
- No file mounting needed
- Works well with temporary credentials (SSO)

**Cons:**
- Need to extract and manage access keys
- Environment variables visible in pod spec

### Option 3: Use Node IAM Role (If Available)

If your EKS nodes already have an IAM role with CloudWatch permissions:

**Remove these from deployment:**
```yaml
# Remove volumeMounts section
# Remove volumes section
# Remove AWS_PROFILE env var
```

Boto3 will automatically use the node's IAM role.

## Troubleshooting

### Pods Not Starting

```bash
kubectl describe pod -n jarvis-demo -l app=cloudwatch-mcp
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --previous
```

**Common issues:**
- Secret not found: `kubectl get secret aws-credentials -n jarvis-demo`
- Wrong secret format: `kubectl get secret aws-credentials -n jarvis-demo -o yaml`

### Permission Errors

```bash
# Check logs for "AccessDenied" or "PermissionDenied"
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp | grep -i denied

# Verify your AWS user has CloudWatch read permissions
aws cloudwatch describe-alarms --max-records 1 --region us-east-1

# If using temporary credentials (SSO), check expiration
aws sts get-caller-identity
```

### Credentials Not Being Used

```bash
# Get shell in pod
kubectl exec -it -n jarvis-demo $(kubectl get pod -n jarvis-demo -l app=cloudwatch-mcp -o jsonpath='{.items[0].metadata.name}') -- sh

# Inside pod, check:
echo $AWS_PROFILE  # Should show "default"
ls -la /home/app/.aws  # Should show credentials file
cat /home/app/.aws/credentials  # Should show your credentials

# Or check environment variables (if using Option B):
env | grep AWS_ACCESS_KEY_ID
env | grep AWS_SECRET_ACCESS_KEY
```

## Updating Credentials

### If Using Profiles (Option A)

```bash
# Update local credentials
# Then recreate secret:
kubectl delete secret aws-credentials -n jarvis-demo
kubectl create secret generic aws-credentials \
  --from-file=credentials=$HOME/.aws/credentials \
  --from-file=config=$HOME/.aws/config \
  -n jarvis-demo

# Restart pods
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

### If Using Access Keys (Option B)

```bash
# Get new credentials, then:
kubectl delete secret aws-credentials -n jarvis-demo
kubectl create secret generic aws-credentials \
  --from-literal=access-key-id=NEW_ACCESS_KEY_ID \
  --from-literal=secret-access-key=NEW_SECRET_ACCESS_KEY \
  -n jarvis-demo

# Restart pods
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

## Security Notes for Testing

⚠️ **This configuration is for TESTING only:**

- Your AWS credentials are stored in Kubernetes secrets
- No per-user authentication (anyone with cluster access can use it)
- Single set of credentials shared across all requests
- Suitable for development/testing, not production

**For production:**
- Use IAM Identity Center OIDC (when you get permissions)
- Follow `IAM_IDENTITY_CENTER_SETUP.md`
- Switch to `deployment.yaml` (auth enabled)

## What's Configured

✅ `ENABLE_AUTH=false` - No user authentication required
✅ Uses your existing AWS credentials
✅ Single replica for testing
✅ Health checks enabled
✅ Logs accessible via kubectl
✅ Service available on port 3334

## Architecture

```
Your Request → MCP Server (no auth) → AWS CloudWatch APIs
                        ↓
                Your AWS User Credentials
                (from secret/mounted files)
```

## Next Steps

After testing works:

1. **Test all tools:**
   - `get_active_alarms`
   - `describe_log_groups`
   - `execute_log_insights_query`
   - `get_metric_data`

2. **Verify permissions:**
   - Check you can read all log groups you need
   - Test across different regions if needed

3. **Plan for production:**
   - Request IAM Identity Center OIDC app permissions
   - Follow `IAM_IDENTITY_CENTER_SETUP.md`
   - Migrate to auth-enabled deployment

## Quick Commands Reference

```bash
# Deploy
kubectl apply -f k8s/jarvis-demo/deployment-no-auth.yaml

# Status
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp

# Logs
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp -f

# Port forward
kubectl port-forward -n jarvis-demo svc/cloudwatch-mcp 3334:3334

# Update credentials
kubectl delete secret aws-credentials -n jarvis-demo
kubectl create secret generic aws-credentials --from-file=credentials=$HOME/.aws/credentials -n jarvis-demo
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo

# Delete deployment
kubectl delete -f k8s/jarvis-demo/deployment-no-auth.yaml
```

---

**Time to deploy: ~5 minutes** 🚀