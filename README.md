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

CloudWatch MCP is deployed to EKS using **IRSA (IAM Roles for Service Accounts)** for secure, credential-free AWS authentication:

```
┌─────────────────────────────────────┐
│   Jarvis (LibreChat Client)        │
│   http://cloudwatch-mcp:3334/mcp   │
└──────────────┬──────────────────────┘
               │ streamable-http
               ↓
┌─────────────────────────────────────┐
│   CloudWatch MCP Server Pod         │
│   Service Account: cloudwatch-mcp-  │
│   service-account                   │
└──────────────┬──────────────────────┘
               │ IRSA
               ↓
┌─────────────────────────────────────┐
│   IAM Role:                         │
│   CloudWatchMCPServerRole           │
│   - CloudWatch Read Permissions     │
└─────────────────────────────────────┘
```

### Configuration

Deployed via [jarvis-deployment](https://github.com/your-org/jarvis-deployment) Terraform in `ascending/saas-account/terraform/jarvis-demo/values.yaml`:

```yaml
mcpConfigs:
  - name: cloudwatch-mcp
    enabled: true
    image:
      repository: 897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server
      tag: latest
    serviceAccount:
      name: cloudwatch-mcp-service-account
      annotations:
        eks.amazonaws.com/role-arn: "arn:aws:iam::897729109735:role/CloudWatchMCPServerRole"
    service:
      port: 3334
```

Client configuration (Jarvis):

```yaml
mcpServers:
  cloudwatch:
    type: streamable-http
    url: http://cloudwatch-mcp:3334/mcp
    timeout: 120000
```

### Deployment Workflow

1. **Build & Push**: GitHub Action builds Docker image → pushes to ECR
2. **Infrastructure**: Terraform in jarvis-deployment manages:
   - IAM role (CloudWatchMCPServerRole)
   - Service account with IRSA annotation
   - Kubernetes deployment
3. **Deploy**: Terraform apply pulls latest image from ECR

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
│   ├── middleware.py          # Auth middleware
│   ├── cloudwatch_logs/       # Logs tools
│   ├── cloudwatch_metrics/    # Metrics tools
│   └── cloudwatch_alarms/     # Alarms tools
├── tests/                     # Test suite
├── pyproject.toml            # Dependencies
└── Dockerfile                # Container image
```

## CI/CD

### GitHub Actions

- **Build**: [`.github/workflows/ci-cloudwatch.yml`](.github/workflows/ci-cloudwatch.yml)
  - Builds multi-arch image (amd64/arm64)
  - Pushes to ECR: `897729109735.dkr.ecr.us-east-1.amazonaws.com/jarvis/cloudwatch_mcp_server`

- **Deploy**: [`.github/workflows/deploy-cloudwatch.yml`](.github/workflows/deploy-cloudwatch.yml)
  - Applies Kubernetes manifests
  - Triggers pod rollout

### Manual Deployment

Deployment is managed through Terraform in the `jarvis-deployment` repository:

```bash
# In jarvis-deployment repo
cd ascending/saas-account/terraform/jarvis-demo

# Pull latest changes
git pull origin main

# Review changes
terraform plan

# Apply
terraform apply
```

## IAM Configuration

The CloudWatch MCP server requires the following IAM permissions (managed via Terraform):

**Trust Policy** (IRSA):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::897729109735:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/..."
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringLike": {
        "oidc.eks....:sub": "system:serviceaccount:*:cloudwatch-mcp-service-account"
      }
    }
  }]
}
```

**Permissions Policy**:
- `cloudwatch:DescribeAlarms`
- `cloudwatch:GetMetricData`
- `cloudwatch:ListMetrics`
- `logs:DescribeLogGroups`
- `logs:FilterLogEvents`
- `logs:GetLogEvents`
- `logs:StartQuery`

See [`iam/`](iam/) directory for reference policy templates.

## Documentation

- [Developer Guide](DEVELOPER_GUIDE.md) - Contributing and development
- [Deployment Guide](docs/DEPLOYMENT.md) - Docker deployment options
- [EKS Deployment](docs/DEPLOYMENT_EKS.md) - Kubernetes/EKS details

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Create feature branch from `main`
2. Make changes and test locally
3. Build and test Docker image
4. Create PR to `main`
5. After merge, GitHub Actions builds and pushes to ECR
6. Update Terraform in jarvis-deployment repo
7. Apply Terraform changes to deploy

## Security

- Uses IRSA for AWS authentication (no static credentials)
- Never commit credential files (enforced via `.gitignore`)
- Follows AWS IAM least privilege principle
- All secrets managed via AWS Secrets Manager

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
