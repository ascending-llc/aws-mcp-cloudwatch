#!/bin/bash
# Script to refresh AWS SSO credentials for CloudWatch MCP server in jarvis-demo
# Usage: ./refresh-cloudwatch-creds.sh

set -e

PROFILE="saas"
NAMESPACE="jarvis-demo"
SECRET_NAME="aws-credentials"  # pragma: allowlist secret
DEPLOYMENT="cloudwatch-mcp"

echo "🔐 Logging in to AWS SSO for profile: $PROFILE"
aws sso login --profile "$PROFILE"

echo "✅ SSO login successful"
echo ""

echo "📋 Extracting temporary credentials..."
CREDS=$(aws configure export-credentials --profile "$PROFILE" --format env)

# Extract the values
ACCESS_KEY=$(echo "$CREDS" | grep AWS_ACCESS_KEY_ID | cut -d'=' -f2)
SECRET_KEY=$(echo "$CREDS" | grep AWS_SECRET_ACCESS_KEY | cut -d'=' -f2)
SESSION_TOKEN=$(echo "$CREDS" | grep AWS_SESSION_TOKEN | cut -d'=' -f2)
EXPIRATION=$(echo "$CREDS" | grep AWS_CREDENTIAL_EXPIRATION | cut -d'=' -f2)

echo "✅ Credentials extracted"
echo "   Expiration: $EXPIRATION"
echo ""

echo "📝 Creating temporary credential files..."
cat > /tmp/aws-credentials << EOF
[saas]
aws_access_key_id=$ACCESS_KEY
aws_secret_access_key=$SECRET_KEY
aws_session_token=$SESSION_TOKEN
EOF

cat > /tmp/aws-config << EOF
[profile saas]
region = us-east-1
output = json
EOF

echo "✅ Credential files created"
echo ""

echo "🔄 Updating Kubernetes secret: $SECRET_NAME in namespace: $NAMESPACE"
# Delete old secret if it exists
kubectl delete secret "$SECRET_NAME" -n "$NAMESPACE" --ignore-not-found=true

# Create new secret
kubectl create secret generic "$SECRET_NAME" \
  --from-file=config=/tmp/aws-config \
  --from-file=credentials=/tmp/aws-credentials \
  -n "$NAMESPACE"

echo "✅ Secret updated"
echo ""

echo "🔄 Restarting deployment: $DEPLOYMENT"
kubectl rollout restart deployment/"$DEPLOYMENT" -n "$NAMESPACE"
kubectl rollout status deployment/"$DEPLOYMENT" -n "$NAMESPACE" --timeout=60s

echo "✅ Deployment restarted successfully"
echo ""

echo "🧹 Cleaning up temporary files..."
rm -f /tmp/aws-credentials /tmp/aws-config

echo ""
echo "✅ All done! CloudWatch MCP server is running with fresh credentials."
echo "   Credentials expire at: $EXPIRATION"
echo ""
echo "🔍 Check logs with:"
echo "   kubectl logs -n $NAMESPACE -l app=$DEPLOYMENT --tail=50"
echo ""
echo "🧪 Test the server with:"
echo "   curl http://localhost:3334/mcp (after port-forward)"
