#!/bin/bash
set -e

echo "🚀 CloudWatch MCP - Testing Deployment Script"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="jarvis-demo"
ECR_REGISTRY="897729109735.dkr.ecr.us-east-1.amazonaws.com"
ECR_REPO="jarvis/cloudwatch_mcp_server"
IMAGE_TAG="${IMAGE_TAG:-latest}"
AWS_PROFILE="saas"
REGION="us-east-1"
EKS_CLUSTER="ascending-s-api-cluster"

echo "Configuration:"
echo "  AWS Profile: $AWS_PROFILE"
echo "  Region: $REGION"
echo "  Namespace: $NAMESPACE"
echo "  ECR: $ECR_REGISTRY/$ECR_REPO:$IMAGE_TAG"
echo "  EKS Cluster: $EKS_CLUSTER"
echo ""

# Step 1: Verify Prerequisites
echo "📋 Step 1: Checking Prerequisites..."
echo "-----------------------------------"

# Check AWS authentication
echo -n "  ✓ AWS Authentication: "
if aws sts get-caller-identity --profile $AWS_PROFILE --region $REGION > /dev/null 2>&1; then
    ACCOUNT_ID=$(aws sts get-caller-identity --profile $AWS_PROFILE --region $REGION --query Account --output text)
    USER_ARN=$(aws sts get-caller-identity --profile $AWS_PROFILE --region $REGION --query Arn --output text)
    echo -e "${GREEN}OK${NC}"
    echo "    Account: $ACCOUNT_ID"
    echo "    Identity: $USER_ARN"
else
    echo -e "${RED}FAILED${NC}"
    echo "    Please run: aws sso login --profile YOUR_PROFILE"
    exit 1
fi

# Check kubectl
echo -n "  ✓ kubectl: "
if command -v kubectl > /dev/null 2>&1; then
    KUBECTL_VERSION=$(kubectl version --client --short 2>/dev/null || kubectl version --client 2>&1 | head -1)
    echo -e "${GREEN}OK${NC} ($KUBECTL_VERSION)"
else
    echo -e "${RED}FAILED${NC}"
    echo "    Please install kubectl"
    exit 1
fi

# Check Docker
echo -n "  ✓ Docker: "
if command -v docker > /dev/null 2>&1; then
    DOCKER_VERSION=$(docker --version)
    echo -e "${GREEN}OK${NC} ($DOCKER_VERSION)"
else
    echo -e "${YELLOW}NOT FOUND${NC}"
    echo "    Docker not required if using GitHub Actions for build"
fi

echo ""

# Step 2: Configure EKS Access
echo "🔧 Step 2: Configuring EKS Access..."
echo "------------------------------------"

echo -n "  Updating kubeconfig for $EKS_CLUSTER... "
if aws eks update-kubeconfig --name $EKS_CLUSTER --profile $AWS_PROFILE --region $REGION > /dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "    Do you have access to the EKS cluster?"
    exit 1
fi

echo -n "  Testing cluster access... "
if kubectl get nodes > /dev/null 2>&1; then
    NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
    echo -e "${GREEN}OK${NC} ($NODE_COUNT nodes)"
else
    echo -e "${RED}FAILED${NC}"
    exit 1
fi

# Check if namespace exists
echo -n "  Checking namespace $NAMESPACE... "
if kubectl get namespace $NAMESPACE > /dev/null 2>&1; then
    echo -e "${GREEN}EXISTS${NC}"
else
    echo -e "${YELLOW}NOT FOUND${NC}"
    echo -n "  Creating namespace $NAMESPACE... "
    kubectl create namespace $NAMESPACE
    echo -e "${GREEN}CREATED${NC}"
fi

echo ""

# Step 3: Create AWS Credentials Secret
echo "🔐 Step 3: Setting Up AWS Credentials..."
echo "-----------------------------------------"

# Check if secret already exists
if kubectl get secret aws-credentials -n $NAMESPACE > /dev/null 2>&1; then
    echo -e "${YELLOW}  Secret 'aws-credentials' already exists${NC}"
    read -p "  Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "  Deleting existing secret..."
        kubectl delete secret aws-credentials -n $NAMESPACE
    else
        echo "  Using existing secret"
        SECRET_CREATED=false
    fi
else
    SECRET_CREATED=true
fi

if [ "$SECRET_CREATED" != "false" ]; then
    echo ""
    echo "  Choose credential method:"
    echo "    1) Use ~/.aws/credentials file (recommended for SSO)"
    echo "    2) Enter access keys manually"
    echo ""
    read -p "  Enter choice (1 or 2): " -n 1 -r CRED_CHOICE
    echo ""
    echo ""

    case $CRED_CHOICE in
        1)
            echo "  Using ~/.aws/credentials and ~/.aws/config files..."
            if [ -f ~/.aws/credentials ] && [ -f ~/.aws/config ]; then
                kubectl create secret generic aws-credentials \
                    --from-file=credentials=$HOME/.aws/credentials \
                    --from-file=config=$HOME/.aws/config \
                    -n $NAMESPACE
                echo -e "  ${GREEN}✓ Secret created from AWS files${NC}"
            else
                echo -e "  ${RED}✗ AWS credential files not found${NC}"
                echo "    Please run: aws sso login --profile YOUR_PROFILE"
                exit 1
            fi
            ;;
        2)
            echo "  Enter AWS credentials:"
            read -p "    AWS Access Key ID: " AWS_ACCESS_KEY_ID
            read -sp "    AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY
            echo ""
            read -p "    AWS Session Token (optional, press Enter to skip): " AWS_SESSION_TOKEN
            echo ""

            if [ -z "$AWS_SESSION_TOKEN" ]; then
                kubectl create secret generic aws-credentials \
                    --from-literal=access-key-id="$AWS_ACCESS_KEY_ID" \
                    --from-literal=secret-access-key="$AWS_SECRET_ACCESS_KEY" \
                    -n $NAMESPACE
            else
                kubectl create secret generic aws-credentials \
                    --from-literal=access-key-id="$AWS_ACCESS_KEY_ID" \
                    --from-literal=secret-access-key="$AWS_SECRET_ACCESS_KEY" \
                    --from-literal=session-token="$AWS_SESSION_TOKEN" \
                    -n $NAMESPACE
            fi
            echo -e "  ${GREEN}✓ Secret created from access keys${NC}"

            # Update deployment to use access keys
            echo -e "  ${YELLOW}Note: You need to update deployment-no-auth.yaml to use access keys${NC}"
            echo "    Uncomment lines 49-64 and comment out line 46 (AWS_PROFILE)"
            ;;
        *)
            echo -e "  ${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
fi

echo ""

# Step 4: Build Docker Image (Optional)
echo "🐳 Step 4: Docker Image..."
echo "--------------------------"

echo "  Do you want to build the Docker image now?"
echo "    1) Yes, build locally and push to ECR"
echo "    2) No, I'll use GitHub Actions (recommended)"
echo "    3) Skip, image already exists"
echo ""
read -p "  Enter choice (1, 2, or 3): " -n 1 -r BUILD_CHOICE
echo ""
echo ""

case $BUILD_CHOICE in
    1)
        echo "  Building Docker image locally..."
        cd src/cloudwatch-mcp-server

        # Login to ECR
        echo "  Logging into ECR..."
        aws ecr get-login-password --profile $AWS_PROFILE --region $REGION | \
            docker login --username AWS --password-stdin $ECR_REGISTRY

        # Build image
        echo "  Building image..."
        docker build -t $ECR_REGISTRY/$ECR_REPO:$IMAGE_TAG .

        # Push image
        echo "  Pushing image to ECR..."
        docker push $ECR_REGISTRY/$ECR_REPO:$IMAGE_TAG

        echo -e "  ${GREEN}✓ Image built and pushed${NC}"
        cd ../..
        ;;
    2)
        echo -e "  ${YELLOW}Please trigger GitHub Actions workflow:${NC}"
        echo "    gh workflow run ci-cloudwatch.yml -f region=$REGION"
        echo ""
        read -p "  Press Enter when GitHub Actions build is complete..."
        ;;
    3)
        echo "  Skipping image build..."
        ;;
    *)
        echo -e "  ${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""

# Step 5: Deploy to Kubernetes
echo "☸️  Step 5: Deploying to Kubernetes..."
echo "--------------------------------------"

echo "  Applying deployment manifest..."
kubectl apply -f k8s/jarvis-demo/deployment-no-auth.yaml

echo ""
echo "  Waiting for deployment to be ready..."
kubectl rollout status deployment/cloudwatch-mcp -n $NAMESPACE --timeout=5m

echo ""
echo -e "${GREEN}✓ Deployment complete!${NC}"

echo ""

# Step 6: Verify Deployment
echo "✅ Step 6: Verifying Deployment..."
echo "----------------------------------"

echo "  Pod status:"
kubectl get pods -n $NAMESPACE -l app=cloudwatch-mcp

echo ""
echo "  Service:"
kubectl get svc -n $NAMESPACE cloudwatch-mcp

echo ""
echo "  Recent logs:"
kubectl logs -n $NAMESPACE -l app=cloudwatch-mcp --tail=20

echo ""
echo "=============================================="
echo -e "${GREEN}🎉 Deployment Successful!${NC}"
echo "=============================================="
echo ""
echo "Next steps:"
echo ""
echo "  1. Test health endpoint:"
echo "     kubectl port-forward -n $NAMESPACE svc/cloudwatch-mcp 3334:3334"
echo "     curl http://localhost:3334/health"
echo ""
echo "  2. Test CloudWatch access:"
echo "     curl -X POST http://localhost:3334/mcp/tools/call \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"name\": \"get_active_alarms\", \"arguments\": {\"region\": \"us-east-1\"}}'"
echo ""
echo "  3. View logs:"
echo "     kubectl logs -n $NAMESPACE -l app=cloudwatch-mcp -f"
echo ""
echo "  4. Delete deployment:"
echo "     kubectl delete -f k8s/jarvis-demo/deployment-no-auth.yaml"
echo ""
