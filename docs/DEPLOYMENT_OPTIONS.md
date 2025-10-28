# CloudWatch MCP Server - Deployment Options

Quick reference for choosing and deploying with or without user authentication.

## Two Deployment Modes

### Option 1: With User Authentication (Production)

**Configuration:** `k8s/jarvis-demo/deployment.yaml`

**Authentication Flow:**
```
User → OIDC Token → MCP Server validates token → AssumeRole with token → CloudWatch APIs
```

**Requirements:**
- IAM Identity Center OIDC application
- External Secrets with OIDC config
- Users obtain OIDC tokens before calling MCP

**Pros:**
- Per-user access control
- User identity in CloudTrail logs
- Secure for multi-user environments
- Production-ready

**Cons:**
- Requires OIDC app creation permissions
- More complex setup
- Users need to authenticate

**Setup:** See `IAM_IDENTITY_CENTER_SETUP.md`

---

### Option 2: Without User Authentication (Internal/Dev)

**Configuration:** `k8s/jarvis-demo/deployment-no-auth.yaml`

**Authentication Flow:**
```
User → MCP Server (no validation) → IRSA Role → CloudWatch APIs
```

**Requirements:**
- IAM role for EKS service account (IRSA)
- OIDC provider for EKS cluster (not for users)
- Network policies for access control

**Pros:**
- No OIDC app permissions needed
- Simpler setup
- Works immediately
- Good for internal tools

**Cons:**
- No per-user access control
- All requests use same IAM role
- Requires alternative access controls

**Setup:** See `k8s/jarvis-demo/DEPLOYMENT_NO_AUTH.md`

---

## Quick Comparison

| Feature | With Auth | Without Auth |
|---------|-----------|--------------|
| **User Authentication** | Yes (OIDC) | No |
| **AWS Access** | Per-user assume role | Shared IRSA role |
| **Setup Complexity** | High | Medium |
| **OIDC App Required** | Yes | No |
| **CloudTrail User ID** | Individual users | Service account |
| **Access Control** | User tokens | Network policies |
| **Best For** | Production, multi-user | Internal, single tenant |

---

## Decision Guide

### Choose **WITH Authentication** if:
- ✅ You have IAM Identity Center OIDC app permissions
- ✅ You need per-user access control
- ✅ You need user audit trails in CloudTrail
- ✅ Multiple teams/users will access the service
- ✅ You're deploying to production

### Choose **WITHOUT Authentication** if:
- ✅ You lack OIDC app creation permissions (temporary)
- ✅ Internal tool with trusted users only
- ✅ Access controlled at Kubernetes level
- ✅ Single application consuming the service
- ✅ Development/testing environment

---

## Deployment Steps

### Option 1: With Authentication

```bash
# 1. Complete IAM Identity Center setup
# Follow: src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md

# 2. Configure External Secrets
# Add OIDC config to jarvis-env secret store

# 3. Build image
gh workflow run ci-cloudwatch.yml -f region=us-east-1

# 4. Deploy
kubectl apply -f k8s/jarvis-demo/deployment.yaml
```

### Option 2: Without Authentication

```bash
# 1. Create IRSA role
# Follow: k8s/jarvis-demo/DEPLOYMENT_NO_AUTH.md steps 1-3

# 2. Update deployment with role ARN
sed -i "s/ACCOUNT_ID/$(aws sts get-caller-identity --query Account --output text)/" \
  k8s/jarvis-demo/deployment-no-auth.yaml

# 3. Build image
gh workflow run ci-cloudwatch.yml -f region=us-east-1

# 4. Deploy
kubectl apply -f k8s/jarvis-demo/deployment-no-auth.yaml
```

---

## Your Situation: Deploy Without Auth Now

**Current Status:**
- ❌ Don't have OIDC app creation permissions
- ✅ Have AWS IAM role creation permissions
- ✅ Want to deploy and test now

**Recommended Path:**

1. **Now:** Deploy without authentication
   - Follow `k8s/jarvis-demo/DEPLOYMENT_NO_AUTH.md`
   - Uses IRSA for AWS access
   - Works immediately
   - Secure for internal use

2. **Later:** Migrate to authentication when you get permissions
   - Complete IAM Identity Center setup
   - Switch to `deployment.yaml`
   - Update clients to send Bearer tokens

**Migration is simple** - just a deployment update:
```bash
# Switch from no-auth to auth
kubectl apply -f k8s/jarvis-demo/deployment.yaml
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

---

## Security Notes

### Without Auth Security Checklist

Since user authentication is disabled, ensure:

- [ ] **Kubernetes RBAC** configured to limit service access
- [ ] **NetworkPolicy** restricts ingress to approved pods
- [ ] **IAM role** has least privilege (read-only CloudWatch)
- [ ] **Service** is ClusterIP only (not exposed externally)
- [ ] **Audit logs** enabled at Kubernetes level
- [ ] **Resource quotas** set to prevent abuse

Example NetworkPolicy:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloudwatch-mcp-policy
  namespace: jarvis-demo
spec:
  podSelector:
    matchLabels:
      app: cloudwatch-mcp
  policyTypes: [Ingress]
  ingress:
    - from:
      - podSelector:
          matchLabels:
            app: librechat  # Only librechat can access
      ports: [{protocol: TCP, port: 3334}]
```

---

## Getting Started Right Now

**Fastest path to deployment:**

```bash
# 1. Setup IRSA (15 minutes)
cd k8s/jarvis-demo
# Follow DEPLOYMENT_NO_AUTH.md steps 1-3

# 2. Build & Push (5 minutes)
gh workflow run ci-cloudwatch.yml -f region=us-east-1

# 3. Deploy (2 minutes)
kubectl apply -f deployment-no-auth.yaml

# 4. Verify (1 minute)
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp
```

**Total time: ~23 minutes** to working deployment! 🚀

---

## References

- **With Auth Setup:** `src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md`
- **Without Auth Setup:** `k8s/jarvis-demo/DEPLOYMENT_NO_AUTH.md`
- **EKS Deployment Guide:** `src/cloudwatch-mcp-server/DEPLOYMENT_EKS.md`
- **Kubernetes Operations:** `k8s/jarvis-demo/README.md`
- **CI/CD Overview:** `CICD_IMPLEMENTATION_SUMMARY.md`