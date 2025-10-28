# CloudWatch MCP Server - EKS Deployment Guide

This guide provides comprehensive instructions for deploying the CloudWatch MCP Server to Amazon EKS for the Jarvis Demo environment.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [ECR Repository Setup](#ecr-repository-setup)
4. [IAM Configuration](#iam-configuration)
5. [External Secrets Configuration](#external-secrets-configuration)
6. [Deployment Methods](#deployment-methods)
7. [Verification & Testing](#verification--testing)
8. [Monitoring & Operations](#monitoring--operations)
9. [Troubleshooting](#troubleshooting)

## Overview

The CloudWatch MCP Server is deployed to the `ascending-s-api-cluster` EKS cluster in the `jarvis-demo` namespace. It integrates with the Jarvis Demo LibreChat deployment and uses IAM Identity Center for authentication.

### Architecture

```
GitHub Actions → ECR (Docker Image) → EKS Deployment → CloudWatch MCP Pod(s)
                                            ↓
                            IAM Identity Center (Auth)
                                            ↓
                            AWS CloudWatch (Logs/Metrics/Alarms)
```

### Key Components

- **EKS Cluster:** `ascending-s-api-cluster`
- **Namespace:** `jarvis-demo` or `jarvis`
- **Deployment:** `cloudwatch-mcp`
- **Service:** `cloudwatch-mcp` (ClusterIP on port 3334)
- **ECR Repository:** `jarvis/cloudwatch_mcp_server`

## Prerequisites

### Required Tools

```bash
# AWS CLI
aws --version  # >= 2.0

# kubectl
kubectl version --client  # >= 1.28

# GitHub CLI (optional, for workflow triggers)
gh --version

# Docker (for local testing)
docker --version
```

### Required Access

1. **AWS Account Access:**
   - IAM permissions to assume `SAAS_AWS_DEPLOY_ROLE_ARN`
   - EKS cluster access (`ascending-s-api-cluster`)
   - ECR repository access (registry `897729109735`)

2. **GitHub Access:**
   - Repository access to trigger workflows
   - Secret `SAAS_AWS_DEPLOY_ROLE_ARN` configured

3. **IAM Identity Center:**
   - OIDC application configured (see [IAM_IDENTITY_CENTER_SETUP.md](./IAM_IDENTITY_CENTER_SETUP.md))
   - CloudWatch IAM role created and configured

## ECR Repository Setup

### Create ECR Repository

If the repository doesn't exist, create it:

```bash
aws ecr create-repository \
  --repository-name jarvis/cloudwatch_mcp_server \
  --region us-east-1 \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=AES256
```

### Configure Repository Policy

```bash
# Allow EKS service account to pull images
cat > ecr-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEKSPull",
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ]
    }
  ]
}
EOF

aws ecr set-repository-policy \
  --repository-name jarvis/cloudwatch_mcp_server \
  --policy-text file://ecr-policy.json \
  --region us-east-1
```

### Verify Repository

```bash
aws ecr describe-repositories \
  --repository-names jarvis/cloudwatch_mcp_server \
  --region us-east-1
```

## IAM Configuration

### 1. CloudWatch Role for AssumeRole

The CloudWatch MCP server assumes an IAM role to access CloudWatch APIs. Create this role following [IAM_IDENTITY_CENTER_SETUP.md](./IAM_IDENTITY_CENTER_SETUP.md).

**Role Name:** `CloudWatchMCPRole` (or custom name)

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/oidc.us-east-1.amazonaws.com/id/IDENTITY_CENTER_ID"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.us-east-1.amazonaws.com/id/IDENTITY_CENTER_ID:aud": "YOUR_CLIENT_ID"
        }
      }
    }
  ]
}
```

**Permissions:**
```bash
aws iam attach-role-policy \
  --role-name CloudWatchMCPRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess
```

### 2. EKS Service Account (Optional - IRSA)

For enhanced security, use IAM Roles for Service Accounts:

```bash
# Create OIDC provider for EKS (if not exists)
eksctl utils associate-iam-oidc-provider \
  --cluster ascending-s-api-cluster \
  --region us-east-1 \
  --approve

# Create service account with IAM role
eksctl create iamserviceaccount \
  --cluster ascending-s-api-cluster \
  --namespace jarvis-demo \
  --name cloudwatch-mcp-sa \
  --attach-policy-arn arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess \
  --approve \
  --region us-east-1
```

## External Secrets Configuration

The CloudWatch MCP server requires IAM Identity Center credentials stored as External Secrets.

### 1. Verify External Secrets Operator

```bash
# Check if External Secrets Operator is installed
kubectl get pods -n external-secrets-system

# Verify SecretStore exists
kubectl get secretstore -n jarvis-demo jarvis-env
```

### 2. Add Required Secrets

Add the following secrets to your secret management system (AWS Secrets Manager, Parameter Store, etc.):

```bash
# Example using AWS Secrets Manager
aws secretsmanager create-secret \
  --name jarvis-demo/cloudwatch-mcp/iam-identity-center \
  --secret-string '{
    "AWS_IDENTITY_CENTER_ISSUER": "https://portal.sso.us-east-1.amazonaws.com/...",
    "AWS_IDENTITY_CENTER_CLIENT_ID": "your-client-id",
    "AWS_CLOUDWATCH_ROLE_ARN": "arn:aws:iam::ACCOUNT_ID:role/CloudWatchMCPRole"
  }' \
  --region us-east-1
```

### 3. Configure External Secret

The External Secret is defined in `k8s/jarvis-demo/deployment.yaml`. Verify it's properly configured:

```bash
kubectl get externalsecret -n jarvis-demo cloudwatch-mcp-secrets
kubectl describe externalsecret -n jarvis-demo cloudwatch-mcp-secrets
```

### 4. Force Secret Sync

```bash
kubectl annotate es jarvis-env force-sync=$(date +%s) --overwrite -n jarvis-demo
```

## Deployment Methods

### Method 1: GitHub Actions (Recommended)

#### Step 1: Build and Push Docker Image

```bash
# Trigger via GitHub UI:
# Actions → "Build and Push CloudWatch MCP to ECR Registry"

# Or via GitHub CLI:
gh workflow run ci-cloudwatch.yml \
  -f region=us-east-1 \
  -f release_version=0.1.0  # Optional
```

**What this does:**
- Builds multi-arch Docker image (amd64, arm64)
- Pushes to ECR with tags: `latest`, `<commit-sha>`, `<release-version>` (optional)
- Displays build summary

**Verify:**
```bash
aws ecr describe-images \
  --repository-name jarvis/cloudwatch_mcp_server \
  --region us-east-1 \
  --query 'imageDetails[*].[imageTags[0],imagePushedAt]' \
  --output table
```

#### Step 2: Deploy to EKS

```bash
# Trigger via GitHub UI:
# Actions → "Deploy CloudWatch MCP to EKS"

# Or via GitHub CLI:
gh workflow run deploy-cloudwatch.yml \
  -f region=us-east-1 \
  -f application=jarvis-demo \
  -f version=latest  # or specific version like 0.1.0
```

**What this does:**
1. Validates AWS connection
2. Updates kubeconfig for EKS cluster
3. Syncs environment variables (External Secrets)
4. Updates deployment image
5. Restarts pods
6. Verifies rollout status

**Monitor deployment:**
```bash
# Via GitHub Actions logs in the UI
# Or check EKS directly:
kubectl rollout status deploy/cloudwatch-mcp -n jarvis-demo
```

### Method 2: Manual kubectl Deployment

For direct control or troubleshooting:

#### Step 1: Configure kubectl

```bash
# Update kubeconfig
aws eks update-kubeconfig \
  --name ascending-s-api-cluster \
  --region us-east-1

# Verify access
kubectl get nodes
kubectl get ns jarvis-demo
```

#### Step 2: Apply Manifests

```bash
# Navigate to k8s directory
cd k8s/jarvis-demo

# Apply deployment
kubectl apply -f deployment.yaml

# Verify deployment
kubectl get deploy,svc,pods -n jarvis-demo -l app=cloudwatch-mcp
```

#### Step 3: Update Image (if needed)

```bash
kubectl set image deploy/cloudwatch-mcp \
  cloudwatch-mcp=897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server:0.1.0 \
  -n jarvis-demo

kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

### Method 3: Helm (Future)

Prepared for future Helm chart migration:

```bash
# When Helm chart is available:
helm upgrade --install cloudwatch-mcp ./helm-chart \
  --namespace jarvis-demo \
  --values k8s/jarvis-demo/values.yaml \
  --create-namespace
```

## Verification & Testing

### 1. Check Deployment Status

```bash
# View deployment
kubectl get deploy cloudwatch-mcp -n jarvis-demo

# View pods
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp

# View service
kubectl get svc cloudwatch-mcp -n jarvis-demo
```

### 2. Check Pod Logs

```bash
# View recent logs
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=100

# Follow logs in real-time
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp -f

# View logs for specific pod
kubectl logs -n jarvis-demo <pod-name>
```

### 3. Test Health Endpoint

```bash
# Port-forward to local machine
kubectl port-forward -n jarvis-demo svc/cloudwatch-mcp 3334:3334

# In another terminal, test health endpoint
curl http://localhost:3334/health

# Expected response: HTTP 200 OK
```

### 4. Test Authentication

```bash
# Get an OIDC token from IAM Identity Center
TOKEN="your-oidc-token"

# Test authenticated endpoint
curl -X POST http://localhost:3334/mcp/tools/call \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_active_alarms",
    "arguments": {
      "max_items": 5,
      "region": "us-east-1"
    }
  }'
```

### 5. Verify External Secrets

```bash
# Check External Secret status
kubectl get externalsecret cloudwatch-mcp-secrets -n jarvis-demo

# View secret (keys only, not values)
kubectl describe secret cloudwatch-mcp-secrets -n jarvis-demo

# Verify secret has required keys
kubectl get secret cloudwatch-mcp-secrets -n jarvis-demo -o jsonpath='{.data}' | jq 'keys'
```

## Monitoring & Operations

### Monitoring Deployment

```bash
# Watch pod status
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp -w

# View resource usage
kubectl top pods -n jarvis-demo -l app=cloudwatch-mcp

# View events
kubectl get events -n jarvis-demo --field-selector involvedObject.name=cloudwatch-mcp --sort-by='.lastTimestamp'
```

### Scaling

```bash
# Manual scaling
kubectl scale deploy/cloudwatch-mcp --replicas=3 -n jarvis-demo

# Verify scaling
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp

# Auto-scaling (HPA)
kubectl autoscale deploy/cloudwatch-mcp \
  --cpu-percent=70 \
  --min=2 \
  --max=10 \
  -n jarvis-demo
```

### Updating Configuration

```bash
# Update environment variables
kubectl set env deploy/cloudwatch-mcp FASTMCP_LOG_LEVEL=DEBUG -n jarvis-demo

# Restart pods to apply changes
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

### Rollback

```bash
# View rollout history
kubectl rollout history deploy/cloudwatch-mcp -n jarvis-demo

# Rollback to previous version
kubectl rollout undo deploy/cloudwatch-mcp -n jarvis-demo

# Rollback to specific revision
kubectl rollout undo deploy/cloudwatch-mcp --to-revision=2 -n jarvis-demo
```

## Troubleshooting

### Common Issues

#### 1. Pods Not Starting

**Symptoms:** Pods stuck in `Pending` or `CrashLoopBackOff`

**Diagnosis:**
```bash
kubectl describe pod -n jarvis-demo -l app=cloudwatch-mcp
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --previous
```

**Common causes:**
- Image pull errors (check ECR permissions)
- Resource limits too low
- Missing secrets
- Port conflicts

#### 2. Image Pull Errors

**Symptoms:** `ErrImagePull` or `ImagePullBackOff`

**Diagnosis:**
```bash
kubectl describe pod -n jarvis-demo -l app=cloudwatch-mcp | grep -A 10 "Events:"
```

**Solution:**
```bash
# Verify image exists in ECR
aws ecr describe-images \
  --repository-name jarvis/cloudwatch_mcp_server \
  --region us-east-1

# Check ECR login permissions
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 897729109735.dkr.ecr.us-east-1.amazonaws.com
```

#### 3. Authentication Errors

**Symptoms:** 401 Unauthorized errors in logs

**Diagnosis:**
```bash
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp | grep -i "auth\|401\|unauthorized"
```

**Solution:**
```bash
# Verify external secrets are synced
kubectl get externalsecret cloudwatch-mcp-secrets -n jarvis-demo -o yaml

# Check secret values exist (not empty)
kubectl get secret cloudwatch-mcp-secrets -n jarvis-demo -o yaml

# Force secret refresh
kubectl annotate es jarvis-env force-sync=$(date +%s) --overwrite -n jarvis-demo

# Restart pods after secret refresh
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
```

#### 4. Health Check Failures

**Symptoms:** Pods restarting due to liveness probe failures

**Diagnosis:**
```bash
kubectl describe pod -n jarvis-demo -l app=cloudwatch-mcp | grep -A 5 "Liveness:"
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=50
```

**Solution:**
```bash
# Increase probe delays if startup is slow
kubectl patch deploy/cloudwatch-mcp -n jarvis-demo -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "cloudwatch-mcp",
          "livenessProbe": {
            "initialDelaySeconds": 60
          }
        }]
      }
    }
  }
}'
```

#### 5. Connection to AWS Services Failing

**Symptoms:** AWS API errors in logs

**Diagnosis:**
```bash
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp | grep -i "aws\|cloudwatch\|sts"
```

**Solution:**
```bash
# Verify IAM role ARN is correct
kubectl get secret cloudwatch-mcp-secrets -n jarvis-demo -o jsonpath='{.data.AWS_CLOUDWATCH_ROLE_ARN}' | base64 -d

# Test AWS connectivity from pod
kubectl exec -it -n jarvis-demo <pod-name> -- sh
# Inside pod:
# aws sts get-caller-identity
# aws cloudwatch describe-alarms --max-records 1 --region us-east-1
```

### Debugging Commands

```bash
# Get shell in pod
kubectl exec -it -n jarvis-demo <pod-name> -- sh

# View all pod details
kubectl get pod -n jarvis-demo <pod-name> -o yaml

# Check pod resource usage
kubectl top pod -n jarvis-demo <pod-name>

# View deployment YAML
kubectl get deploy cloudwatch-mcp -n jarvis-demo -o yaml

# Check service endpoints
kubectl get endpoints cloudwatch-mcp -n jarvis-demo
```

## Security Best Practices

1. **Use IRSA (IAM Roles for Service Accounts):**
   - More secure than embedding credentials
   - Automatic credential rotation

2. **Network Policies:**
   - Restrict ingress/egress traffic
   - Only allow necessary connections

3. **Pod Security Standards:**
   - Run as non-root (UID 1000)
   - Read-only root filesystem
   - Drop all capabilities

4. **Secret Management:**
   - Use External Secrets Operator
   - Regular credential rotation
   - Audit secret access via CloudTrail

5. **Image Security:**
   - Use signed images
   - Enable ECR image scanning
   - Regularly update base images

## Integration with Jarvis Demo

### Service Discovery

The CloudWatch MCP server is accessible within the cluster at:

```
cloudwatch-mcp.jarvis-demo.svc.cluster.local:3334
```

### LibreChat Integration

Configure LibreChat to use the CloudWatch MCP server:

```yaml
# LibreChat configuration
mcp_servers:
  - name: cloudwatch
    url: http://cloudwatch-mcp.jarvis-demo.svc.cluster.local:3334
    auth:
      type: bearer
      token: ${IAM_IDENTITY_CENTER_TOKEN}
```

### Testing from LibreChat Pod

```bash
# Get shell in LibreChat pod
kubectl exec -it -n jarvis-demo <librechat-pod> -- sh

# Test connection
curl http://cloudwatch-mcp.jarvis-demo.svc.cluster.local:3334/health
```

## Maintenance

### Regular Tasks

1. **Update Images:**
   - Build new images with security patches
   - Test in staging before production
   - Deploy via GitHub Actions

2. **Monitor Logs:**
   - Set up log aggregation (CloudWatch Logs, ELK, etc.)
   - Configure alerts for errors

3. **Review Metrics:**
   - CPU/Memory usage
   - Request rates
   - Error rates

4. **Credential Rotation:**
   - Rotate IAM Identity Center credentials quarterly
   - Update External Secrets

## References

- [Kubernetes Documentation](k8s/jarvis-demo/README.md)
- [IAM Identity Center Setup](IAM_IDENTITY_CENTER_SETUP.md)
- [Authentication Changes Review](AUTHENTICATION_CHANGES_REVIEW.md)
- [Main README](README.md)
- [AWS EKS Documentation](https://docs.aws.amazon.com/eks/)
- [External Secrets Operator](https://external-secrets.io/)

## Support

For issues or questions:
1. Check pod logs and events
2. Review troubleshooting section above
3. Consult Kubernetes documentation
4. Contact DevOps team for EKS cluster issues
