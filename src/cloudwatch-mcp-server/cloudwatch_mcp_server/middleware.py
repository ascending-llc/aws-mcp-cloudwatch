"""Authentication middleware for CloudWatch MCP Server."""

import os
from typing import Optional
import boto3
import jwt
from jwt import PyJWKClient
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class CognitoAuthMiddleware(BaseHTTPMiddleware):
    """Middleware to validate Cognito JWT tokens and provide AWS credentials.

    This middleware:
    1. Extracts JWT token from Authorization header
    2. Validates token against Cognito User Pool
    3. Exchanges token for temporary AWS credentials via Identity Pool
    4. Attaches credentials to request.state for tools to use
    """

    def __init__(self, app, enable_auth: bool = True):
        """Initialize the middleware.

        Args:
            app: The ASGI application
            enable_auth: Whether to enable authentication (default: True)
                        Set to False for local development
        """
        super().__init__(app)
        self.enable_auth = enable_auth

        # Cognito configuration
        self.cognito_region = os.getenv('AWS_COGNITO_REGION', 'us-east-1')
        self.user_pool_id = os.getenv('AWS_COGNITO_USER_POOL_ID')
        self.client_id = os.getenv('AWS_COGNITO_CLIENT_ID')
        self.identity_pool_id = os.getenv('AWS_COGNITO_IDENTITY_POOL_ID')

        # JWKS client for token verification
        if self.enable_auth and self.user_pool_id:
            jwks_url = (
                f"https://cognito-idp.{self.cognito_region}.amazonaws.com/"
                f"{self.user_pool_id}/.well-known/jwks.json"
            )
            self.jwks_client = PyJWKClient(jwks_url, cache_keys=True)
            logger.info(f"Cognito auth middleware initialized for pool: {self.user_pool_id}")
        else:
            self.jwks_client = None
            logger.warning("Auth middleware running in DISABLED mode")

    async def dispatch(self, request: Request, call_next):
        """Process each request through the middleware.

        Args:
            request: The incoming request
            call_next: The next middleware/handler in the chain

        Returns:
            Response from the next handler, or 401 if auth fails
        """
        # Skip auth for health checks and non-MCP endpoints
        if request.url.path in ['/health', '/']:
            return await call_next(request)

        # If auth is disabled, proceed without validation
        if not self.enable_auth:
            logger.debug("Auth disabled, skipping validation")
            return await call_next(request)

        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning("Missing or invalid Authorization header")
            return JSONResponse(
                status_code=401,
                content={'error': 'Missing or invalid Authorization header'}
            )

        token = auth_header.replace('Bearer ', '')

        try:
            # Verify JWT token
            token_payload = await self._verify_token(token)

            # Get AWS credentials from Cognito Identity Pool
            aws_credentials = await self._get_aws_credentials(token, token_payload)

            # Attach credentials and user info to request state
            request.state.aws_credentials = aws_credentials
            request.state.user_email = token_payload.get('email')
            request.state.user_sub = token_payload.get('sub')
            request.state.token_payload = token_payload

            logger.info(f"Authenticated request from user: {request.state.user_email}")

            # Proceed to next handler
            response = await call_next(request)
            return response

        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return JSONResponse(
                status_code=401,
                content={'error': 'Token expired'}
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return JSONResponse(
                status_code=401,
                content={'error': f'Invalid token: {str(e)}'}
            )
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={'error': 'Authentication failed'}
            )

    async def _verify_token(self, token: str) -> dict:
        """Verify JWT token from Cognito.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            jwt.InvalidTokenError: If token is invalid
        """
        # Get signing key from JWKS
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)

        # Verify and decode token
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            audience=self.client_id,
            issuer=f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.user_pool_id}"
        )

        return payload

    async def _get_aws_credentials(self, token: str, token_payload: dict) -> dict:
        """Exchange Cognito token for temporary AWS credentials.

        Args:
            token: Cognito JWT token
            token_payload: Decoded token payload

        Returns:
            Dictionary with AWS credentials:
                - access_key_id
                - secret_access_key
                - session_token
                - expiration
        """
        cognito_identity = boto3.client('cognito-identity', region_name=self.cognito_region)

        # Construct the provider name for Cognito
        provider_name = f'cognito-idp.{self.cognito_region}.amazonaws.com/{self.user_pool_id}'

        # Get Identity ID from Cognito Identity Pool
        identity_response = cognito_identity.get_id(
            IdentityPoolId=self.identity_pool_id,
            Logins={provider_name: token}
        )

        identity_id = identity_response['IdentityId']
        logger.debug(f"Got identity ID: {identity_id}")

        # Get temporary AWS credentials for this identity
        credentials_response = cognito_identity.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={provider_name: token}
        )

        creds = credentials_response['Credentials']

        return {
            'access_key_id': creds['AccessKeyId'],
            'secret_access_key': creds['SecretAccessKey'],
            'session_token': creds['SessionToken'],
            'expiration': creds['Expiration']
        }


class IAMIdentityCenterMiddleware(BaseHTTPMiddleware):
    """Middleware for AWS IAM Identity Center (formerly AWS SSO) authentication.

    This middleware validates OIDC tokens from IAM Identity Center and
    assumes the appropriate IAM role for CloudWatch access.
    """

    def __init__(self, app, enable_auth: Optional[bool] = None):
        """Initialize the middleware.

        Args:
            app: The ASGI application
            enable_auth: Whether to enable authentication
        """
        super().__init__(app)
        if enable_auth is None:
            enable_auth = os.getenv('ENABLE_AUTH', 'true').lower() == 'true'
        self.enable_auth = enable_auth

        self.region = os.getenv('AWS_IDENTITY_CENTER_REGION', 'us-east-1')
        self.issuer = os.getenv('AWS_IDENTITY_CENTER_ISSUER')
        self.client_id = os.getenv('AWS_IDENTITY_CENTER_CLIENT_ID')
        self.role_arn = os.getenv('AWS_CLOUDWATCH_ROLE_ARN')

        if self.enable_auth and self.issuer:
            jwks_url = f"{self.issuer}/.well-known/jwks.json"
            self.jwks_client = PyJWKClient(jwks_url, cache_keys=True)
            logger.info(f"IAM Identity Center middleware initialized: {self.issuer}")
        else:
            self.jwks_client = None
            logger.warning("IAM Identity Center middleware running in DISABLED mode")

    async def dispatch(self, request: Request, call_next):
        """Process each request through the middleware."""
        # Skip auth for health checks
        if request.url.path in ['/health', '/']:
            return await call_next(request)

        if not self.enable_auth:
            return await call_next(request)

        # Extract token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JSONResponse(
                status_code=401,
                content={'error': 'Missing Authorization header'}
            )

        token = auth_header.replace('Bearer ', '')

        try:
            # Verify token
            token_payload = await self._verify_token(token)

            # Assume role using the token
            aws_credentials = await self._assume_role(token_payload)

            # Attach to request state
            request.state.aws_credentials = aws_credentials
            request.state.user_email = token_payload.get('email')
            request.state.token_payload = token_payload

            logger.info(f"Authenticated IAM Identity Center user: {request.state.user_email}")

            return await call_next(request)

        except Exception as e:
            logger.error(f"IAM Identity Center auth error: {str(e)}")
            return JSONResponse(
                status_code=401,
                content={'error': 'Authentication failed'}
            )

    async def _verify_token(self, token: str) -> dict:
        """Verify OIDC token from IAM Identity Center."""
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            audience=self.client_id,
            issuer=self.issuer
        )

        return payload

    async def _assume_role(self, token_payload: dict) -> dict:
        """Assume IAM role for CloudWatch access."""
        sts_client = boto3.client('sts', region_name=self.region)

        # Use role ARN from env or from token custom claim
        role_arn = self.role_arn or token_payload.get('custom:role_arn')

        if not role_arn:
            raise ValueError("No role ARN configured")

        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"cloudwatch-mcp-{token_payload.get('sub')[:32]}",
            DurationSeconds=3600
        )

        return {
            'access_key_id': response['Credentials']['AccessKeyId'],
            'secret_access_key': response['Credentials']['SecretAccessKey'],
            'session_token': response['Credentials']['SessionToken'],
            'expiration': response['Credentials']['Expiration']
        }


class OIDCMiddleware(BaseHTTPMiddleware):
    """Generic OIDC middleware for third-party providers (Okta, Auth0, etc.).

    This middleware validates OIDC tokens and exchanges them for AWS credentials
    using AssumeRoleWithWebIdentity.
    """

    def __init__(self, app, enable_auth: bool = True):
        """Initialize the middleware."""
        super().__init__(app)
        self.enable_auth = enable_auth

        self.issuer = os.getenv('OIDC_ISSUER')
        self.client_id = os.getenv('OIDC_CLIENT_ID')
        self.role_arn = os.getenv('AWS_CLOUDWATCH_ROLE_ARN')

        if self.enable_auth and self.issuer:
            jwks_url = f"{self.issuer}/.well-known/jwks.json"
            self.jwks_client = PyJWKClient(jwks_url, cache_keys=True)
            logger.info(f"OIDC middleware initialized: {self.issuer}")
        else:
            self.jwks_client = None
            logger.warning("OIDC middleware running in DISABLED mode")

    async def dispatch(self, request: Request, call_next):
        """Process each request."""
        if request.url.path in ['/health', '/']:
            return await call_next(request)

        if not self.enable_auth:
            return await call_next(request)

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JSONResponse(
                status_code=401,
                content={'error': 'Missing Authorization header'}
            )

        token = auth_header.replace('Bearer ', '')

        try:
            token_payload = await self._verify_token(token)
            aws_credentials = await self._get_aws_credentials(token)

            request.state.aws_credentials = aws_credentials
            request.state.user_email = token_payload.get('email')
            request.state.token_payload = token_payload

            logger.info(f"Authenticated OIDC user: {request.state.user_email}")

            return await call_next(request)

        except Exception as e:
            logger.error(f"OIDC auth error: {str(e)}")
            return JSONResponse(
                status_code=401,
                content={'error': 'Authentication failed'}
            )

    async def _verify_token(self, token: str) -> dict:
        """Verify OIDC token."""
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            audience=self.client_id,
            issuer=self.issuer
        )

        return payload

    async def _get_aws_credentials(self, token: str) -> dict:
        """Exchange OIDC token for AWS credentials."""
        sts_client = boto3.client('sts')

        response = sts_client.assume_role_with_web_identity(
            RoleArn=self.role_arn,
            RoleSessionName='cloudwatch-mcp-session',
            WebIdentityToken=token,
            DurationSeconds=3600
        )

        return {
            'access_key_id': response['Credentials']['AccessKeyId'],
            'secret_access_key': response['Credentials']['SecretAccessKey'],
            'session_token': response['Credentials']['SessionToken'],
            'expiration': response['Credentials']['Expiration']
        }
