# CloudWatch MCP Server

A Model Context Protocol (MCP) server providing AI assistants access to AWS CloudWatch metrics, logs, and alarms for operational monitoring and troubleshooting.

[![License](https://img.shields.io/badge/license-Apache--2.0-brightgreen)](LICENSE)

## Overview

CloudWatch MCP Server enables AI assistants to query and analyze AWS CloudWatch data through a standardized MCP interface. Built with [FastMCP](https://gofastmcp.com/), it provides tools for logs analysis, metrics monitoring, and alarm management.

### Key Features

- **CloudWatch Logs**: Search and filter log events across log groups
- **CloudWatch Metrics**: Query metrics, statistics, and performance data
- **CloudWatch Alarms**: Monitor alarm states and history
- **Pre-indexed Metadata**: 1,179 AWS metrics indexed for fast lookup

## Production Deployment

### Architecture

CloudWatch MCP is deployed to EKS using **IRSA (IAM Roles for Service Accounts)** for secure, credential-free AWS authentication. The server runs in both production (`jarvis`) and demo (`jarvis-demo`) namespaces, sharing the same ECR image and IAM role.

```
┌─────────────────────────────────────┐
│   Jarvis (LibreChat Client)        │
│   http://cloudwatch-mcp:3334/mcp   │
└──────────────┬──────────────────────┘
               │ streamable-http
               ↓
┌─────────────────────────────────────┐
│   CloudWatch MCP Server Pod         │
│   Namespaces: jarvis, jarvis-demo   │
│   Service Account: cloudwatch-mcp-  │
│   service-account                   │
└──────────────┬──────────────────────┘
               │ IRSA
               ↓
┌─────────────────────────────────────┐
│   IAM Role:                         │
│   CloudWatchMCPServerRole           │
│   - CloudWatch Read Permissions     │
│   - Wildcard namespace support      │
└─────────────────────────────────────┘
```

### Configuration

Deployed via [jarvis-deployment](https://github.com/your-org/jarvis-deployment) Terraform in both `ascending/saas-account/terraform/jarvis/values.yaml` and `ascending/saas-account/terraform/jarvis-demo/values.yaml`:

**Infrastructure Configuration** (mcpConfigs):
```yaml
mcpConfigs:
  - name: cloudwatch-mcp
    enabled: true
    image:
      repository: 897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server
      tag: latest
      pullPolicy: Always
    serviceAccount:
      name: cloudwatch-mcp-service-account
      annotations:
        eks.amazonaws.com/role-arn: "arn:aws:iam::897729109735:role/CloudWatchMCPServerRole"
    service:
      port: 3334
```

**Client Configuration** (mcpServers):
```yaml
mcpServers:
  cloudwatch:
    type: streamable-http
    url: http://cloudwatch-mcp:3334/mcp
    timeout: 120000
```

### Deployment Workflow

1. **Build & Push**: GitHub Action (`.github/workflows/ci-cloudwatch.yml`) builds Docker image and pushes to ECR
2. **Infrastructure**: Terraform in jarvis-deployment manages:
   - IAM role (CloudWatchMCPServerRole) with wildcard namespace trust policy
   - Service accounts with IRSA annotations in both namespaces
   - Kubernetes deployments in jarvis and jarvis-demo
3. **Deploy**: Terraform apply pulls latest image from ECR
4. **Update**: After new image push, manually restart deployments:
   ```bash
   kubectl rollout restart deployment/cloudwatch-mcp -n jarvis
   kubectl rollout restart deployment/cloudwatch-mcp -n jarvis-demo
   ```

### Verifying Deployment

Check deployment status:
```bash
# Check pods are running
kubectl get pods -n jarvis -l app=cloudwatch-mcp
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp

# Verify IRSA configuration
kubectl exec -n jarvis deployment/cloudwatch-mcp -- env | grep AWS_ROLE_ARN

# Check CloudWatch access
kubectl exec -n jarvis deployment/cloudwatch-mcp -- \
  aws cloudwatch describe-alarms --max-records 1
```

## Local Development

### Prerequisites

- Python 3.9+
- [uv](https://docs.astral.sh/uv/) package manager
- AWS credentials configured

### Setup

```bash
# Clone repository
git clone https://github.com/your-org/aws-mcp-cloudwatch.git
cd aws-mcp-cloudwatch/src/cloudwatch-mcp-server

# Install dependencies
uv sync

# Run server
uv run cloudwatch_mcp_server
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region | `us-east-1` |
| `AWS_PROFILE` | AWS profile (local dev) | - |
| `CLOUDWATCH_MCP_PORT` | Server port | `3334` |
| `CLOUDWATCH_MCP_SERVER_HOST` | Server host | `0.0.0.0` |
| `FASTMCP_LOG_LEVEL` | Log level | `INFO` |

### Testing Locally

```bash
# Run tests
cd src/cloudwatch-mcp-server
uv run pytest

# Test with MCP client (e.g., Cursor)
# Add to .cursor/mcp.json:
{
  "mcpServers": {
    "cloudwatch": {
      "command": "uvx",
      "args": ["cloudwatch-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## Available MCP Tools

### CloudWatch Logs
- `search_log_events` - Search across log groups
- `filter_log_streams` - Filter log streams
- `describe_log_groups` - List log groups

### CloudWatch Metrics
- `get_metric_statistics` - Get metric stats
- `list_metrics` - List available metrics
- `get_metric_data` - Retrieve metric data

### CloudWatch Alarms
- `describe_alarms` - List alarms
- `get_alarm_history` - Get alarm history

## Project Structure

```
src/cloudwatch-mcp-server/
├── cloudwatch_mcp_server/
│   ├── server.py              # Main entry point
│   ├── __init__.py
│   ├── _future_auth/          # Archived authentication middleware
│   ├── cloudwatch_logs/       # Logs tools
│   ├── cloudwatch_metrics/    # Metrics tools
│   └── cloudwatch_alarms/     # Alarms tools
├── tests/                     # Test suite
├── pyproject.toml            # Dependencies
└── Dockerfile                # Container image
```

## Authentication

**Current**: CloudWatch MCP uses IRSA (IAM Roles for Service Accounts) for AWS authentication. Authentication middleware implementations (OAuth, OIDC, Cognito) are archived in `src/cloudwatch-mcp-server/cloudwatch_mcp_server/_future_auth/` for potential future use but are not currently active.

## CI/CD

### GitHub Actions

- **Build**: [`.github/workflows/ci-cloudwatch.yml`](.github/workflows/ci-cloudwatch.yml)
  - Builds multi-arch image (amd64/arm64)
  - Pushes to ECR: `897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server:latest`
  - Triggered on push to main or manual dispatch

- **Deploy**: [`.github/workflows/deploy-cloudwatch.yml`](.github/workflows/deploy-cloudwatch.yml)
  - Applies Kubernetes service account with IRSA
  - Applies deployment manifest to jarvis-demo namespace
  - Note: Manual restart required for pods to pull new image

### Manual Deployment

Deployment is managed through Terraform in the `jarvis-deployment` repository:

```bash
# In jarvis-deployment repo
cd ascending/saas-account/terraform/jarvis

# Pull latest changes
git pull origin main

# Review changes
terraform plan

# Apply to both environments
terraform apply

# Restart pods to pull new image (if ECR image updated)
kubectl rollout restart deployment/cloudwatch-mcp -n jarvis
kubectl rollout restart deployment/cloudwatch-mcp -n jarvis-demo
```

## IAM Configuration

The CloudWatch MCP server uses a shared IAM role across both namespaces. Reference policy files are available in the `iam/` directory.

**Trust Policy** (IRSA with wildcard namespace):
- File: [`iam/cloudwatch-mcp-trust-policy.json`](iam/cloudwatch-mcp-trust-policy.json)
- Allows: `system:serviceaccount:*:cloudwatch-mcp-service-account`
- Supports both jarvis and jarvis-demo namespaces

**Permissions Policy**:
- File: [`iam/cloudwatch-mcp-permissions-policy.json`](iam/cloudwatch-mcp-permissions-policy.json)
- CloudWatch permissions:
  - `cloudwatch:DescribeAlarms`
  - `cloudwatch:GetMetricData`
  - `cloudwatch:ListMetrics`
- CloudWatch Logs permissions:
  - `logs:DescribeLogGroups`
  - `logs:FilterLogEvents`
  - `logs:GetLogEvents`
  - `logs:StartQuery`

## Documentation

- [Developer Guide](DEVELOPER_GUIDE.md) - Contributing and development
- [Contributing Guidelines](CONTRIBUTING.md) - How to contribute
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community standards
- [docs/CLAUDE.md](docs/CLAUDE.md) - AI assistant integration notes
- [docs/authentication/](docs/authentication/) - Authentication implementation details

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Create feature branch from `main`
2. Make changes and test locally with `uv run cloudwatch_mcp_server`
3. Run tests: `uv run pytest`
4. Build and test Docker image locally
5. Create PR to `main`
6. After merge, GitHub Actions builds and pushes to ECR
7. Update Terraform in jarvis-deployment repo if config changes needed
8. Apply Terraform changes to deploy
9. Restart deployments to pull new image

## Security

- Uses IRSA for AWS authentication (no static credentials in pods)
- IAM role follows least privilege principle (read-only CloudWatch access)
- Credential files excluded via `.gitignore` (patterns: `*creds*.json`, `cloudwatch-*.json`)
- Service account with IRSA annotation provides secure credential injection
- No per-user authentication implemented (service-level access only)

## License

Licensed under Apache 2.0 - see [LICENSE](LICENSE) file.

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/aws-mcp-cloudwatch/issues)
- **Internal**: ASCENDING Slack #jarvis-support

---

**Related Projects**:
- [jarvis-deployment](https://github.com/your-org/jarvis-deployment) - Infrastructure & Terraform
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [FastMCP](https://gofastmcp.com/) - Python MCP framework
