# Deployment Guide

This document outlines the deployment strategy for the CloudWatch MCP Server fork with OAuth and CI/CD integration.

## Phase 1: Docker HTTP Transport Testing ✓ (Current Phase)

### Testing Locally

1. **Run the test script:**
   ```bash
   ./test-docker-http.sh
   ```

2. **Manual testing steps:**
   ```bash
   # Build the image
   docker build -t cloudwatch-mcp-server .

   # Run with AWS credentials
   docker run -d \
     --name cloudwatch-mcp \
     -p 3334:3334 \
     -e AWS_REGION=us-east-1 \
     -e AWS_PROFILE=your-profile \
     -e FASTMCP_LOG_LEVEL=INFO \
     -v ~/.aws:/root/.aws:ro \
     cloudwatch-mcp-server

   # Check logs
   docker logs -f cloudwatch-mcp

   # Test the endpoint
   curl http://localhost:3334/
   ```

3. **Verify the following:**
   - [ ] Container builds successfully
   - [ ] Container starts and stays running
   - [ ] HTTP server binds to port 3334
   - [ ] Server responds to HTTP requests
   - [ ] AWS credentials are accessible (check logs)
   - [ ] MCP tools are registered and available

### Known Configuration

The server is configured for HTTP transport in:
- **Dockerfile**: Exposes port 3334, sets `CLOUDWATCH_MCP_SERVER_HOST=0.0.0.0`
- **server.py**: Uses `transport="streamable-http"` with configurable host/port
- **Environment variables:**
  - `CLOUDWATCH_MCP_PORT`: Server port (default: 3334)
  - `CLOUDWATCH_MCP_SERVER_HOST`: Bind address (default: 0.0.0.0)
  - `AWS_REGION`: AWS region (default: us-east-1)
  - `AWS_PROFILE`: AWS credentials profile
  - `FASTMCP_LOG_LEVEL`: Logging level (ERROR, INFO, DEBUG)

---

## Phase 2: OAuth Integration with AWS Signin

### Architecture Options

#### Option A: OAuth with AWS Cognito (Recommended for AWS-native)
```
Client → API Gateway (OAuth validation) → CloudWatch MCP Server
```

**Pros:**
- Native AWS integration
- Built-in user pools and identity federation
- Works with existing AWS IAM policies
- Supports social providers (Google, Facebook) and SAML

**Implementation:**
1. Create Cognito User Pool
2. Configure OAuth 2.0 flows
3. Add API Gateway in front of MCP server
4. Validate JWT tokens in API Gateway
5. Pass AWS credentials to MCP server via assumed role

**Example configuration:**
```python
# In server.py, add JWT validation middleware
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # Verify JWT with Cognito public keys
        payload = jwt.decode(token, cognito_public_key, algorithms=['RS256'])
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

#### Option B: OAuth with Third-Party Provider (Okta, Auth0, etc.)
```
Client → OAuth Provider → Token → MCP Server (validates token)
```

**Pros:**
- Company may already have Okta/Auth0 subscription
- Centralized user management
- Enterprise features (MFA, SSO)

**Implementation:**
1. Register MCP server as OAuth application
2. Implement token validation middleware
3. Map OAuth identity to AWS credentials (via AWS STS)

#### Option C: AWS IAM with Signature V4 (No OAuth, pure AWS)
```
Client → AWS Signature V4 → API Gateway → MCP Server
```

**Pros:**
- Uses existing AWS credentials
- No separate OAuth layer needed
- Leverages IAM policies directly

**Cons:**
- Clients need AWS credentials
- Less flexible for non-AWS users

### Recommended Approach: Cognito + API Gateway

1. **Create CloudFormation/CDK stack:**
   ```yaml
   # infrastructure/cognito-stack.yaml
   Resources:
     UserPool:
       Type: AWS::Cognito::UserPool
       Properties:
         UserPoolName: cloudwatch-mcp-users
         AutoVerifiedAttributes: [email]

     UserPoolClient:
       Type: AWS::Cognito::UserPoolClient
       Properties:
         ClientName: cloudwatch-mcp-client
         UserPoolId: !Ref UserPool
         AllowedOAuthFlows: [authorization_code]
         AllowedOAuthScopes: [openid, profile, email]
   ```

2. **Modify server.py to validate tokens:**
   ```python
   # Add FastAPI dependency for auth
   from fastapi import FastAPI, Depends
   from mcp.server.fastmcp import FastMCP

   # Wrap FastMCP with FastAPI for middleware
   app = FastAPI()

   @app.middleware("http")
   async def auth_middleware(request, call_next):
       # Validate JWT token here
       return await call_next(request)
   ```

3. **Update Dockerfile to include auth dependencies:**
   ```toml
   # In pyproject.toml
   dependencies = [
       # ... existing deps
       "pyjwt[crypto]>=2.8.0",
       "python-jose[cryptography]>=3.3.0",
   ]
   ```

### Testing OAuth Integration

```bash
# Get token from Cognito
TOKEN=$(curl -X POST https://your-domain.auth.us-east-1.amazoncognito.com/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=xxx&client_secret=yyy')

# Test authenticated request
curl -H "Authorization: Bearer $TOKEN" http://localhost:3334/
```

---

## Phase 3: GitHub Actions CI/CD Workflow

### Workflow Structure

```
.github/workflows/
├── test.yml           # Run tests on PR
├── build.yml          # Build and push Docker image
└── deploy-test.yml    # Deploy to test server
```

### Implementation

#### 1. Test Workflow (.github/workflows/test.yml)
```yaml
name: Test CloudWatch MCP Server

on:
  pull_request:
    paths:
      - 'src/cloudwatch-mcp-server/**'
  push:
    branches: [main]
    paths:
      - 'src/cloudwatch-mcp-server/**'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Set up Python
        run: uv python install 3.13

      - name: Install dependencies
        working-directory: src/cloudwatch-mcp-server
        run: uv sync --all-groups

      - name: Run linters
        working-directory: src/cloudwatch-mcp-server
        run: |
          uv run ruff check .
          uv run pyright

      - name: Run tests with coverage
        working-directory: src/cloudwatch-mcp-server
        run: uv run pytest --cov --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          file: src/cloudwatch-mcp-server/coverage.xml
```

#### 2. Build and Push Workflow (.github/workflows/build.yml)
```yaml
name: Build and Push Docker Image

on:
  push:
    branches: [main]
    tags: ['v*']
  workflow_dispatch:

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}/cloudwatch-mcp-server

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=sha

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: src/cloudwatch-mcp-server
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

#### 3. Deploy Workflow (.github/workflows/deploy-test.yml)
```yaml
name: Deploy to Test Server

on:
  workflow_run:
    workflows: ["Build and Push Docker Image"]
    types: [completed]
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}

    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DEPLOY_ROLE_ARN }}
          aws-region: us-east-1

      - name: Deploy to ECS/EC2/EKS
        run: |
          # Option A: Deploy to ECS
          aws ecs update-service \
            --cluster cloudwatch-mcp-test \
            --service cloudwatch-mcp-server \
            --force-new-deployment

          # Option B: Deploy to EC2 via SSH
          # ssh deploy@test-server 'docker pull ... && docker restart ...'

          # Option C: Deploy to EKS
          # kubectl set image deployment/cloudwatch-mcp ...
```

### Required GitHub Secrets

Set these in your repository settings:
- `AWS_DEPLOY_ROLE_ARN`: IAM role ARN for deployment
- `TEST_SERVER_HOST`: Hostname of test server (if deploying to EC2)
- `TEST_SERVER_SSH_KEY`: SSH key for deployment (if using SSH)
- `COGNITO_USER_POOL_ID`: If using Cognito for OAuth
- `COGNITO_CLIENT_ID`: Cognito app client ID

---

## Phase 4: Test Server Configuration

### Deployment Options

#### Option A: AWS ECS Fargate (Recommended for simplicity)
```bash
# Create ECS task definition with your Docker image
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create or update service
aws ecs create-service \
  --cluster cloudwatch-mcp-test \
  --service-name cloudwatch-mcp-server \
  --task-definition cloudwatch-mcp:latest \
  --desired-count 1
```

#### Option B: EC2 with Docker
```bash
# On your test server
docker pull ghcr.io/your-org/cloudwatch-mcp-server:latest
docker run -d \
  --name cloudwatch-mcp \
  --restart unless-stopped \
  -p 3334:3334 \
  -e AWS_REGION=us-east-1 \
  ghcr.io/your-org/cloudwatch-mcp-server:latest
```

#### Option C: Kubernetes/EKS
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudwatch-mcp-server
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: cloudwatch-mcp
        image: ghcr.io/your-org/cloudwatch-mcp-server:latest
        ports:
        - containerPort: 3334
        env:
        - name: AWS_REGION
          value: us-east-1
```

---

## Next Steps Checklist

### Immediate (Today)
- [ ] Run `./test-docker-http.sh` to verify Docker + HTTP transport
- [ ] Test MCP tools via HTTP endpoints
- [ ] Document any issues or required changes

### Short-term (This week)
- [ ] Decide on OAuth provider (Cognito vs existing company solution)
- [ ] Set up Cognito User Pool (if using Cognito)
- [ ] Implement JWT validation in server.py
- [ ] Test OAuth flow locally

### Medium-term (Next 2 weeks)
- [ ] Create GitHub Actions workflows
- [ ] Configure GitHub secrets and deployment credentials
- [ ] Set up test server infrastructure (ECS/EC2/EKS)
- [ ] Deploy first version to test environment
- [ ] Create monitoring and alerting

### Questions to Answer
1. **OAuth**: Does your company already have an OAuth provider (Okta, Auth0, Azure AD)?
2. **Deployment**: Where will the test server run (AWS ECS, EC2, EKS, on-prem)?
3. **AWS Credentials**: How should the MCP server assume AWS roles (IAM roles for pods, instance profiles)?
4. **Networking**: Will the server be publicly accessible or behind VPN?
5. **Secrets Management**: Where will secrets be stored (AWS Secrets Manager, GitHub Secrets)?

---

## Resources

- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [AWS Cognito OAuth Flows](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-integration.html)
- [GitHub Actions for AWS](https://github.com/aws-actions)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
