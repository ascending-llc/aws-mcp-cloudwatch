# CloudWatch MCP Server - Jarvis Demo Deployment Story

## Overview

This document chronicles the journey of deploying and troubleshooting the CloudWatch MCP server to the jarvis-demo Kubernetes cluster for testing and demonstration purposes.

## Initial Context

The CloudWatch MCP server was successfully built and pushed to ECR, and the goal was to integrate it with the jarvis-demo LibreChat UI to demonstrate CloudWatch monitoring capabilities through an AI assistant.

## Deployment Timeline

### Phase 1: Initial Integration (October 28, 2025)

**Goal:** Add CloudWatch MCP server to the jarvis-demo environment and make it accessible through the LibreChat UI.

**Actions Taken:**
1. Verified CloudWatch MCP pod was running in jarvis-demo namespace
2. Examined existing LibreChat ConfigMap to understand MCP server configuration pattern
3. Added CloudWatch MCP server configuration to `librechat.yaml`:
   ```yaml
   cloudwatch:
     type: streamable-http
     url: http://cloudwatch-mcp:3334/mcp
     timeout: 120000
     serverInstructions: |
       # CloudWatch MCP Server Instructions
       You have access to AWS CloudWatch through this MCP server connection...
   ```
4. Updated jarvis-demo ConfigMap and restarted jarvis-api deployment

**Result:** ✅ CloudWatch MCP server appeared in the UI as an available tool

### Phase 2: First Bug - Context Availability (October 28, 2025)

**Problem:** When attempting to use `get_active_alarms` tool, received error:
```
Context is not available outside of a request
```

**Root Cause Investigation:**
- Initial assumption: AWS credential issues with "default" profile not found
- Changed `AWS_PROFILE` from "default" to "saas" in deployment
- Error persisted, revealing deeper issue
- **Actual cause:** Code had `await ctx.error()` calls in exception handlers across multiple files
- When AWS errors occurred, the code tried to use MCP context in exception handlers where it wasn't available
- This masked the actual AWS errors

**Files Affected:**
- `cloudwatch_mcp_server/cloudwatch_alarms/tools.py` (2 instances)
- `cloudwatch_mcp_server/cloudwatch_logs/tools.py` (4 instances)
- `cloudwatch_mcp_server/cloudwatch_metrics/tools.py` (3 instances)

**Fix Applied:**
1. Searched codebase for all `await ctx.error()` patterns
2. Removed 9 total instances from exception handlers
3. Kept `logger.error()` and `raise` statements for proper error handling
4. Committed changes and triggered CI/CD rebuild
5. Deployed updated Docker image to jarvis-demo

**Result:** ✅ Context error resolved, but revealed underlying AWS credential issue

### Phase 3: AWS Credentials Setup (October 28, 2025)

**Problem:** After fixing context bug, received:
```
ProfileNotFound: The config profile (saas) could not be found
```

**Investigation:**
- Discovered `aws-credentials` Kubernetes secret didn't exist (marked as optional in deployment)
- Pod had old credentials for sandbox and ascops profiles with expired SSO tokens
- Needed fresh SSO credentials for saas profile (account 897729109735)

**Solution Implemented:**
1. User logged in to AWS SSO locally: `aws sso login --profile saas`
2. Extracted temporary credentials using: `aws configure export-credentials --profile saas --format env`
3. Created minimal credential files with just saas profile:
   - `/tmp/aws-credentials`: Contains access key, secret key, and session token
   - `/tmp/aws-config`: Contains profile configuration with region and output format
4. Created new Kubernetes secret:
   ```bash
   kubectl create secret generic aws-credentials \
     --from-file=config=/tmp/aws-config \
     --from-file=credentials=/tmp/aws-credentials \
     -n jarvis-demo
   ```
5. Restarted CloudWatch MCP deployment

**Created Automation:**
- Built `scripts/refresh-cloudwatch-creds.sh` script for easy credential renewal
- Script automates: SSO login → extract creds → update secret → restart deployment
- Credentials expire after ~1 hour with SSO tokens

**Result:** ✅ Credentials mounted correctly, but profile still not found

### Phase 4: HOME Environment Variable Fix (October 28, 2025)

**Problem:** Still getting ProfileNotFound error despite credentials being correctly mounted at `/home/app/.aws/`

**Root Cause Discovery:**
- Checked environment variables in pod: `HOME=/`
- boto3 was looking for credentials in `/.aws/` instead of `/home/app/.aws/`
- Credentials were mounted at correct location, but HOME pointed to wrong directory

**Fix Applied:**
1. Added `HOME=/home/app` environment variable to deployment manifest:
   ```yaml
   env:
     - name: HOME
       value: "/home/app"
   ```
2. Applied updated deployment
3. Restarted pod with new configuration

**Result:** ✅ boto3 now finds credentials correctly, server fully operational

## Final Configuration

### Deployment Configuration
**File:** `k8s/jarvis-demo/deployment-no-auth.yaml`

**Key Settings:**
- `ENABLE_AUTH=false` - Authentication disabled for testing
- `AWS_PROFILE=saas` - Using saas profile (account 897729109735)
- `AWS_REGION=us-east-1` - CloudWatch region
- `HOME=/home/app` - **Critical for boto3 to find credentials**
- Credentials mounted from secret at `/home/app/.aws/`

### LibreChat Configuration
**File:** ConfigMap `jarvis-demo/librechat-config`

CloudWatch MCP server entry in `librechat.yaml`:
- Type: streamable-http
- URL: http://cloudwatch-mcp:3334/mcp
- Timeout: 120000ms
- Server instructions provided for AI assistant context

### Credential Management
**Script:** `scripts/refresh-cloudwatch-creds.sh`

Automates credential refresh process:
1. Logs into AWS SSO for saas profile
2. Extracts temporary credentials
3. Updates Kubernetes secret
4. Restarts deployment

**Usage:**
```bash
cd /Users/alexandergroman/Development/aws-mcp-cloudwatch
./scripts/refresh-cloudwatch-creds.sh
```

## Lessons Learned

### 1. Context Lifecycle in MCP Servers
- MCP Context objects are only available within active request handlers
- Never use `ctx.error()` in exception handlers - use `logger.error()` instead
- Let exceptions propagate naturally; MCP framework handles error responses

### 2. boto3 Credential Discovery
- boto3 searches for credentials in `$HOME/.aws/` directory
- Default HOME in containers may not match mount paths
- Always explicitly set HOME environment variable when mounting credentials

### 3. Kubernetes Secret Management
- Secrets marked as `optional: true` won't cause pod failures if missing
- But missing credentials will cause runtime errors when code tries to use them
- Always verify secret exists and is correctly mounted before testing

### 4. SSO Credential Lifecycle
- SSO tokens are temporary (typically 1 hour expiration)
- Not suitable for long-term production deployments
- Good for testing, but production should use IAM roles (IRSA)

### 5. Systematic Debugging Approach
- Check error message → verify configuration → check actual mounted files → verify environment
- Don't assume environment variables have expected values - always verify in pod
- Use `kubectl exec` to inspect actual runtime environment

## Current Status

**Deployment:** ✅ Operational
- Pod running successfully in jarvis-demo namespace
- All health checks passing (200 OK responses)
- Credentials valid until ~2025-10-28T19:57:49+00:00

**Functionality:** ✅ Available for testing
- CloudWatch MCP server appears in LibreChat UI
- All tools available: get_active_alarms, get_alarm_history, log analysis, metrics
- Ready for user testing in jarvis-demo environment

**Limitations:**
- Uses temporary SSO credentials (1-hour expiration)
- No user authentication (ENABLE_AUTH=false)
- Single set of AWS credentials shared by all users
- Not production-ready - intended for testing only

## Testing Checklist

- [x] Pod deployed and running
- [x] Credentials configured and mounted
- [x] HOME environment variable set correctly
- [x] MCP server accessible via Kubernetes service
- [x] Server appears in LibreChat UI
- [ ] **get_active_alarms tool tested in UI**
- [ ] get_alarm_history tool tested
- [ ] CloudWatch Logs tools tested
- [ ] CloudWatch Metrics tools tested

## Support Resources

### Refresh Credentials (when expired)
```bash
./scripts/refresh-cloudwatch-creds.sh
```

### Check Pod Status
```bash
kubectl get pods -n jarvis-demo -l app=cloudwatch-mcp
kubectl logs -n jarvis-demo -l app=cloudwatch-mcp --tail=50
```

### Verify Credentials in Pod
```bash
kubectl exec -n jarvis-demo deployment/cloudwatch-mcp -- env | grep -E "AWS_|HOME"
kubectl exec -n jarvis-demo deployment/cloudwatch-mcp -- cat /home/app/.aws/config
```

### Restart Deployment
```bash
kubectl rollout restart deployment/cloudwatch-mcp -n jarvis-demo
kubectl rollout status deployment/cloudwatch-mcp -n jarvis-demo
```

## Next Steps

See [OAUTH_IMPLEMENTATION_NEXT_STEPS.md](./OAUTH_IMPLEMENTATION_NEXT_STEPS.md) for guidance on implementing production-ready OAuth authentication with user-specific AWS credentials.
