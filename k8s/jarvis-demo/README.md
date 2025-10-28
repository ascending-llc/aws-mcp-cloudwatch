# CloudWatch MCP Server - Kubernetes Deployment for Jarvis Demo

This directory contains Kubernetes manifests and Helm values for deploying the CloudWatch MCP Server to the Jarvis Demo EKS cluster.

## Directory Structure

```
k8s/jarvis-demo/
├── README.md           # This file
├── deployment.yaml     # Reference Kubernetes deployment manifest
└── values.yaml         # Helm values for future Helm chart migration
```

## Deployment Methods

### Method 1: GitHub Actions (Recommended)

The CloudWatch MCP server is deployed using GitHub Actions workflows:

1. **Build & Push to ECR:**
   ```bash
   # Trigger via GitHub UI: Actions → "Build and Push CloudWatch MCP to ECR Registry"
   # Or via gh CLI:
   gh workflow run ci-cloudwatch.yml \
     -f region=us-east-1 \
     -f release_version=0.1.0  # Optional
   ```

2. **Deploy to EKS:**
   ```bash
   # Trigger via GitHub UI: Actions → "Deploy CloudWatch MCP to EKS"
   # Or via gh CLI:
   gh workflow run deploy-cloudwatch.yml \
     -f region=us-east-1 \
     -f application=jarvis-demo \
     -f version=latest
   ```

### Method 2: Manual kubectl Deployment

For direct kubectl deployment using the reference manifests:

```bash
# 1. Ensure you have kubectl configured for the EKS cluster
aws eks update-kubeconfig --name ascending-s-api-cluster --region us-east-1

# 2. Create namespace if it doesn't exist
kubectl create namespace jarvis-demo

# 3. Apply the deployment manifest
kubectl apply -f deployment.yaml

# 4. Verify deployment
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=100

# 5. Check service
kubectl get svc -n jarvis-demo cloudwatch-mcp
```

### Method 3: Helm (Future)

The `values.yaml` file is prepared for future Helm chart migration:

```bash
# When Helm chart is available:
helm upgrade --install cloudwatch-mcp ./helm-chart \
  --namespace jarvis-demo \
  --values k8s/jarvis-demo/values.yaml
```

## Configuration

### Environment Variables

The CloudWatch MCP server requires the following environment variables:

#### Authentication (IAM Identity Center)
- `ENABLE_AUTH` - Enable/disable authentication (default: "true")
- `AWS_IDENTITY_CENTER_REGION` - AWS region for Identity Center (default: "us-east-1")
- `AWS_IDENTITY_CENTER_ISSUER` - OIDC issuer URL (from External Secrets)
- `AWS_IDENTITY_CENTER_CLIENT_ID` - OIDC client ID (from External Secrets)
- `AWS_CLOUDWATCH_ROLE_ARN` - IAM role ARN to assume (from External Secrets)

#### CloudWatch Configuration
- `AWS_REGION` - AWS region for CloudWatch APIs (default: "us-east-1")
- `CLOUDWATCH_MCP_SERVER_HOST` - Server host (default: "0.0.0.0")
- `CLOUDWATCH_MCP_PORT` - Server port (default: "3334")
- `FASTMCP_LOG_LEVEL` - Logging level (default: "INFO")

### External Secrets

The deployment uses External Secrets Operator to sync credentials from the `jarvis-env` SecretStore:

```yaml
# Required secrets in jarvis-env:
- AWS_IDENTITY_CENTER_ISSUER
- AWS_IDENTITY_CENTER_CLIENT_ID
- AWS_CLOUDWATCH_ROLE_ARN
```

To force sync external secrets:
```bash
kubectl annotate es jarvis-env force-sync=$(date +%s) --overwrite -n jarvis-demo
```

## Monitoring & Troubleshooting

### Check Pod Status

```bash
# View pods
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp

# Describe pod
kubectl describe pod -n jarvis-demo -l app=cloudwatch-mcp

# View logs
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=100 -f

# View logs for specific container
kubectl logs -n jarvis-demo deployment/cloudwatch-mcp -c cloudwatch-mcp
```

### Health Checks

```bash
# Port-forward to test locally
kubectl port-forward -n jarvis-demo svc/cloudwatch-mcp 3334:3334

# Test health endpoint
curl http://localhost:3334/health
```

### Common Issues

#### 1. Pods not starting
```bash
# Check events
kubectl get events -n jarvis-demo --sort-by='.lastTimestamp'

# Check pod status
kubectl describe pod -n jarvis-demo -l app=cloudwatch-mcp
```

#### 2. Authentication errors
```bash
# Verify external secrets are synced
kubectl get externalsecrets -n jarvis-demo

# Check secret exists
kubectl get secret cloudwatch-mcp-secrets -n jarvis-demo

# View secret keys (not values)
kubectl describe secret cloudwatch-mcp-secrets -n jarvis-demo
```

#### 3. Image pull errors
```bash
# Verify ECR image exists
aws ecr describe-images \
  --registry-id 897729109735 \
  --repository-name jarvis/cloudwatch_mcp_server \
  --region us-east-1

# Check if pods have ECR pull permissions
kubectl describe pod -n jarvis-demo -l app=cloudwatch-mcp | grep -A 5 "Events:"
```

## Updating Deployment

### Update Image Version

Using GitHub Actions (recommended):
```bash
gh workflow run deploy-cloudwatch.yml \
  -f region=us-east-1 \
  -f application=jarvis-demo \
  -f version=0.1.0  # Specific version
```

Using kubectl:
```bash
kubectl set image deploy/cloudwatch-mcp \
  cloudwatch-mcp=897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server:0.1.0 \
  -n jarvis-demo
```

### Restart Pods

```bash
kubectl rollout restart deploy/cloudwatch-mcp -n jarvis-demo
kubectl rollout status deploy/cloudwatch-mcp -n jarvis-demo
```

### Rollback Deployment

```bash
# View rollout history
kubectl rollout history deploy/cloudwatch-mcp -n jarvis-demo

# Rollback to previous version
kubectl rollout undo deploy/cloudwatch-mcp -n jarvis-demo

# Rollback to specific revision
kubectl rollout undo deploy/cloudwatch-mcp -n jarvis-demo --to-revision=2
```

## Resource Configuration

Default resource allocation:

```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

Adjust in `values.yaml` or `deployment.yaml` as needed based on load testing.

## Scaling

### Manual Scaling

```bash
# Scale replicas
kubectl scale deployment cloudwatch-mcp --replicas=3 -n jarvis-demo

# Verify scaling
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp
```

### Horizontal Pod Autoscaler (HPA)

```bash
# Create HPA (example)
kubectl autoscale deployment cloudwatch-mcp \
  --cpu-percent=70 \
  --min=2 \
  --max=10 \
  -n jarvis-demo

# Check HPA status
kubectl get hpa -n jarvis-demo
```

## Security Considerations

1. **IAM Roles for Service Accounts (IRSA)**
   - Consider using IRSA for AWS credential management
   - Update ServiceAccount annotation with IAM role ARN

2. **Network Policies**
   - Implement NetworkPolicies to restrict pod-to-pod communication
   - Allow only necessary ingress/egress traffic

3. **Pod Security Standards**
   - Deployment runs as non-root user (UID 1000)
   - No privileged escalation allowed
   - Read-only root filesystem (where possible)

4. **Secret Management**
   - Secrets managed via External Secrets Operator
   - Regular rotation of IAM Identity Center credentials
   - Audit secret access via CloudTrail

## Integration with Jarvis Demo

The CloudWatch MCP server integrates with the Jarvis Demo LibreChat deployment:

1. **Service Discovery:** Available at `cloudwatch-mcp.jarvis-demo.svc.cluster.local:3334`
2. **Authentication:** Uses shared IAM Identity Center configuration
3. **Environment Sync:** Syncs with `jarvis-env` External Secret store

### Testing Integration

```bash
# From another pod in the cluster:
curl http://cloudwatch-mcp.jarvis-demo.svc.cluster.local:3334/health

# Test with authentication:
curl -H "Authorization: Bearer $TOKEN" \
  http://cloudwatch-mcp.jarvis-demo.svc.cluster.local:3334/mcp/tools/list
```

## Migration to Helm

When ready to migrate to Helm charts:

1. Create Helm chart structure
2. Use `values.yaml` as base configuration
3. Templatize `deployment.yaml` into Helm templates
4. Add Helm hooks for lifecycle management
5. Update GitHub Actions to use `helm upgrade --install`

## Support

For issues or questions:
1. Check pod logs: `kubectl logs -n jarvis-demo -l app=cloudwatch-mcp`
2. Review deployment events: `kubectl describe deploy/cloudwatch-mcp -n jarvis-demo`
3. Consult main documentation: `/src/cloudwatch-mcp-server/README.md`
4. Review authentication setup: `/src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md`

## References

- [EKS Cluster Documentation](https://docs.aws.amazon.com/eks/)
- [External Secrets Operator](https://external-secrets.io/)
- [IAM Identity Center Setup](../../src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md)
- [CloudWatch MCP Server Documentation](../../src/cloudwatch-mcp-server/README.md)
