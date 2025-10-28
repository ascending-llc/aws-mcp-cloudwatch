# CloudWatch MCP Server - Documentation Index

Welcome to the CloudWatch MCP Server documentation. This index helps you find all guides and references.

## 🚀 Quick Start

- **New to the project?** Start with [`../src/cloudwatch-mcp-server/CLAUDE.md`](../src/cloudwatch-mcp-server/CLAUDE.md)
- **Want to deploy?** See [DEPLOYMENT_OPTIONS.md](DEPLOYMENT_OPTIONS.md)
- **Testing quickly?** See [`../k8s/jarvis-demo/TESTING_SETUP.md`](../k8s/jarvis-demo/TESTING_SETUP.md)

---

## 📚 Documentation Structure

### Reference Documentation (in `docs/`)

These are overview, reference, and review documents:

#### Authentication
- [AWS_AUTH_GUIDE.md](authentication/AWS_AUTH_GUIDE.md) - Overview of AWS authentication options
- [STARLETTE_AUTH_GUIDE.md](authentication/STARLETTE_AUTH_GUIDE.md) - Starlette middleware integration guide
- [IMPLEMENTATION_REVIEW.md](authentication/IMPLEMENTATION_REVIEW.md) - Authentication implementation review

#### CI/CD
- [IMPLEMENTATION_SUMMARY.md](cicd/IMPLEMENTATION_SUMMARY.md) - Complete CI/CD pipeline overview

#### Deployment
- [DEPLOYMENT_OPTIONS.md](DEPLOYMENT_OPTIONS.md) - Choose your deployment method

### Operational Documentation (near files)

These guides stay with their associated operational files:

#### In `src/cloudwatch-mcp-server/`

**Developer Guides:**
- [`CLAUDE.md`](../src/cloudwatch-mcp-server/CLAUDE.md) - Developer quick reference
- [`README.md`](../src/cloudwatch-mcp-server/README.md) - Main project README

**Setup & Deployment:**
- [`IAM_IDENTITY_CENTER_SETUP.md`](../src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md) - IAM Identity Center OIDC setup
- [`DEPLOYMENT_EKS.md`](../src/cloudwatch-mcp-server/DEPLOYMENT_EKS.md) - EKS deployment guide
- [`DEPLOYMENT.md`](../src/cloudwatch-mcp-server/DEPLOYMENT.md) - Docker deployment guide

#### In `k8s/jarvis-demo/`

**Kubernetes Operations:**
- [`README.md`](../k8s/jarvis-demo/README.md) - Kubernetes operations guide
- [`DEPLOYMENT_NO_AUTH.md`](../k8s/jarvis-demo/DEPLOYMENT_NO_AUTH.md) - Deploy without user authentication (IRSA)
- [`TESTING_SETUP.md`](../k8s/jarvis-demo/TESTING_SETUP.md) - Quick testing with your AWS credentials

**Manifests:**
- [`values.yaml`](../k8s/jarvis-demo/values.yaml) - Helm values
- [`deployment.yaml`](../k8s/jarvis-demo/deployment.yaml) - Production deployment (with auth)
- [`deployment-no-auth.yaml`](../k8s/jarvis-demo/deployment-no-auth.yaml) - Testing deployment (no auth)

#### In `.github/workflows/`

**CI/CD Workflows:**
- [`ci-cloudwatch.yml`](../.github/workflows/ci-cloudwatch.yml) - Build and push to ECR
- [`deploy-cloudwatch.yml`](../.github/workflows/deploy-cloudwatch.yml) - Deploy to EKS

---

## 📖 Documentation by Topic

### Authentication & Security

**Overview & Planning:**
- [AWS_AUTH_GUIDE.md](authentication/AWS_AUTH_GUIDE.md) - Compare authentication options (Cognito, IAM Identity Center, OIDC)
- [STARLETTE_AUTH_GUIDE.md](authentication/STARLETTE_AUTH_GUIDE.md) - How middleware authentication works

**Implementation:**
- [`IAM_IDENTITY_CENTER_SETUP.md`](../src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md) - Step-by-step AWS setup commands
- [IMPLEMENTATION_REVIEW.md](authentication/IMPLEMENTATION_REVIEW.md) - Review of what was implemented

**Testing Without Auth:**
- [`TESTING_SETUP.md`](../k8s/jarvis-demo/TESTING_SETUP.md) - Use your existing AWS credentials for testing

### Deployment

**Choosing a Method:**
- [DEPLOYMENT_OPTIONS.md](DEPLOYMENT_OPTIONS.md) - With or without authentication?

**Docker:**
- [`DEPLOYMENT.md`](../src/cloudwatch-mcp-server/DEPLOYMENT.md) - Docker deployment guide

**EKS:**
- [`DEPLOYMENT_EKS.md`](../src/cloudwatch-mcp-server/DEPLOYMENT_EKS.md) - Comprehensive EKS guide
- [`README.md`](../k8s/jarvis-demo/README.md) - Kubernetes operations
- [`DEPLOYMENT_NO_AUTH.md`](../k8s/jarvis-demo/DEPLOYMENT_NO_AUTH.md) - Deploy with IRSA (no user auth)
- [`TESTING_SETUP.md`](../k8s/jarvis-demo/TESTING_SETUP.md) - Quick test deployment

### CI/CD

**Overview:**
- [IMPLEMENTATION_SUMMARY.md](cicd/IMPLEMENTATION_SUMMARY.md) - Complete CI/CD pipeline documentation

**Workflows:**
- [`ci-cloudwatch.yml`](../.github/workflows/ci-cloudwatch.yml) - Build workflow
- [`deploy-cloudwatch.yml`](../.github/workflows/deploy-cloudwatch.yml) - Deploy workflow

### Development

**Getting Started:**
- [`CLAUDE.md`](../src/cloudwatch-mcp-server/CLAUDE.md) - Developer guide with commands and patterns
- [`README.md`](../src/cloudwatch-mcp-server/README.md) - Main project README

---

## 🎯 Common Scenarios

### "I want to deploy for testing"
1. Read: [`TESTING_SETUP.md`](../k8s/jarvis-demo/TESTING_SETUP.md)
2. Use: [`deployment-no-auth.yaml`](../k8s/jarvis-demo/deployment-no-auth.yaml)
3. Reference: [DEPLOYMENT_OPTIONS.md](DEPLOYMENT_OPTIONS.md)

### "I want to deploy to production"
1. Read: [DEPLOYMENT_OPTIONS.md](DEPLOYMENT_OPTIONS.md)
2. Setup auth: [`IAM_IDENTITY_CENTER_SETUP.md`](../src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md)
3. Deploy: [`DEPLOYMENT_EKS.md`](../src/cloudwatch-mcp-server/DEPLOYMENT_EKS.md)
4. Use: [`deployment.yaml`](../k8s/jarvis-demo/deployment.yaml)

### "I want to understand authentication"
1. Overview: [AWS_AUTH_GUIDE.md](authentication/AWS_AUTH_GUIDE.md)
2. Implementation: [STARLETTE_AUTH_GUIDE.md](authentication/STARLETTE_AUTH_GUIDE.md)
3. Setup: [`IAM_IDENTITY_CENTER_SETUP.md`](../src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md)
4. Review: [IMPLEMENTATION_REVIEW.md](authentication/IMPLEMENTATION_REVIEW.md)

### "I want to set up CI/CD"
1. Read: [IMPLEMENTATION_SUMMARY.md](cicd/IMPLEMENTATION_SUMMARY.md)
2. Use workflows: [`ci-cloudwatch.yml`](../.github/workflows/ci-cloudwatch.yml) and [`deploy-cloudwatch.yml`](../.github/workflows/deploy-cloudwatch.yml)

### "I'm developing the code"
1. Start: [`CLAUDE.md`](../src/cloudwatch-mcp-server/CLAUDE.md)
2. Reference: [`README.md`](../src/cloudwatch-mcp-server/README.md)
3. Auth implementation: [IMPLEMENTATION_REVIEW.md](authentication/IMPLEMENTATION_REVIEW.md)

---

## 📂 File Organization Philosophy

**Reference docs** → `docs/` (overviews, comparisons, reviews)
**Operational docs** → Near their files (setup guides, deployment guides)

This keeps:
- Setup guides with the code/manifests they configure
- Deployment guides with the manifests they deploy
- Reference material centralized for easy browsing

---

## 🔄 Documentation Status

All documentation created: **January 27, 2025**

### What's Implemented
✅ Authentication middleware (IAM Identity Center)
✅ CI/CD pipelines (GitHub Actions)
✅ EKS deployment manifests
✅ Testing configuration (no auth)
✅ Comprehensive documentation

### Future Updates
- Add Helm chart when migrated
- Update for multi-region support
- Add monitoring/observability guides

---

## 📞 Getting Help

- **Can't find something?** Check this index
- **Found an issue?** Update the relevant doc near its operational files
- **Need more detail?** Each guide has detailed troubleshooting sections

---

**Last Updated:** January 27, 2025
