"""Authentication middleware for CloudWatch MCP Server."""

import base64
import json
import os
import time
from loguru import logger
from starlette.requests import Request
from starlette.responses import JSONResponse
from typing import Optional


class BrowserCredentialsMiddleware:
    """Middleware for browser-stored AWS credentials (generic for any AWS account).

    This middleware accepts temporary AWS credentials via two methods:
    1. OAuth Bearer token (from OAuth bridge server) - Recommended for LibreChat
    2. X-AWS-Credentials header (legacy browser-based auth)

    Both methods send base64-encoded JSON containing AWS credentials from:
    - aws sts get-session-token (IAM users)
    - aws configure export-credentials (SSO users)

    This approach works for:
    - users without IAM Identity Center
    - External client
    - Testing and development
    - Multi-account flexible
    """

    def __init__(self, app, enable_auth: Optional[bool] = None):
        """Initialize the middleware.

        Args:
            app: The ASGI application
            enable_auth: Whether to enable authentication
        """
        self.app = app
        if enable_auth is None:
            enable_auth = os.getenv('ENABLE_AUTH', 'true').lower() == 'true'
        self.enable_auth = enable_auth

        if self.enable_auth:
            logger.info('Browser credentials middleware initialized')
        else:
            logger.warning('Browser credentials middleware running in DISABLED mode')

    async def __call__(self, scope, receive, send):
        """ASGI middleware implementation.

        Args:
            scope: ASGI scope dict
            receive: ASGI receive callable
            send: ASGI send callable
        """
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        # Create request from scope to access headers and path
        request = Request(scope, receive)

        # Skip auth for health checks and non-MCP endpoints
        if request.url.path in ['/health', '/']:
            await self.app(scope, receive, send)
            return

        # If auth is disabled, proceed without validation
        if not self.enable_auth:
            logger.debug('Auth disabled, skipping validation')
            await self.app(scope, receive, send)
            return

        # Extract credentials from Authorization header (OAuth) or X-AWS-Credentials header (browser)
        creds_header = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            # OAuth Bearer token from LibreChat OAuth flow
            creds_header = auth_header.replace('Bearer ', '').strip()
            logger.info('Using OAuth Bearer token')
        else:
            # Legacy X-AWS-Credentials header for browser-based auth
            creds_header = request.headers.get('X-AWS-Credentials')
            if creds_header:
                logger.info('Using X-AWS-Credentials header')

        if not creds_header:
            logger.warning(
                'Missing AWS credentials (no Authorization or X-AWS-Credentials header)'
            )
            response = JSONResponse(
                status_code=401,
                content={'error': 'Missing AWS credentials. Please authorize CloudWatch MCP.'},
            )
            await response(scope, receive, send)
            return

        try:
            # Decode base64-encoded credentials
            credentials_json = base64.b64decode(creds_header).decode('utf-8')
            credentials = json.loads(credentials_json)

            # Validate required fields
            required_fields = ['accessKeyId', 'secretAccessKey', 'sessionToken']
            missing = [f for f in required_fields if f not in credentials]
            if missing:
                raise ValueError(f'Missing required credential fields: {", ".join(missing)}')

            # Check if credentials are expired
            if 'expiresAt' in credentials:
                if credentials['expiresAt'] < time.time() * 1000:  # expiresAt is in milliseconds
                    logger.warning('Credentials have expired')
                    response = JSONResponse(
                        status_code=401,
                        content={'error': 'AWS credentials have expired. Please re-authorize.'},
                    )
                    await response(scope, receive, send)
                    return

            # Attach credentials to scope state for downstream handlers
            if 'state' not in scope:
                scope['state'] = {}

            scope['state']['aws_credentials'] = {
                'access_key_id': credentials['accessKeyId'],
                'secret_access_key': credentials['secretAccessKey'],
                'session_token': credentials['sessionToken'],
                'expiration': credentials.get('expiresAt'),
                'account_id': credentials.get('accountId', 'unknown'),
            }
            scope['state']['user_email'] = f'aws-account-{credentials.get("accountId", "unknown")}'

            logger.info(
                f'Authenticated browser credentials for account: {credentials.get("accountId", "unknown")}'
            )

            # Proceed to next handler
            await self.app(scope, receive, send)

        except base64.binascii.Error:
            logger.warning('Invalid base64 encoding in credentials')
            response = JSONResponse(
                status_code=401, content={'error': 'Invalid credentials encoding'}
            )
            await response(scope, receive, send)
        except json.JSONDecodeError:
            logger.warning('Invalid JSON in credentials')
            response = JSONResponse(
                status_code=401, content={'error': 'Invalid credentials format'}
            )
            await response(scope, receive, send)
        except ValueError as e:
            logger.warning(f'Credential validation error: {str(e)}')
            response = JSONResponse(status_code=401, content={'error': str(e)})
            await response(scope, receive, send)
        except Exception as e:
            logger.error(f'Browser credentials auth error: {str(e)}')
            response = JSONResponse(status_code=500, content={'error': 'Authentication failed'})
            await response(scope, receive, send)


'''

oauth and other implementations, leaving for now

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
    extracts AWS credentials directly from JWT custom claims.

    IAM Identity Center custom attribute mappings embed temporary AWS credentials
    (access key, secret key, session token) in the JWT token, eliminating the need
    for AssumeRole calls. This is the recommended approach for LibreChat MCP OAuth.
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

            # Extract AWS credentials from JWT custom claims
            aws_credentials = await self._extract_credentials_from_token(token_payload)

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

    async def _extract_credentials_from_token(self, token_payload: dict) -> dict:
        """Extract AWS credentials from IAM Identity Center JWT token.

        IAM Identity Center custom attribute mappings embed AWS credentials
        directly in the JWT token via ${session:access_key_id}, ${session:secret_access_key},
        and ${session:session_token} custom claims.

        This is the recommended approach for LibreChat MCP OAuth integration.

        Args:
            token_payload: Decoded JWT token payload with custom claims

        Returns:
            Dictionary with AWS credentials:
                - access_key_id: AWS access key from jwt claim
                - secret_access_key: AWS secret key from jwt claim
                - session_token: AWS session token from jwt claim
                - expiration: Token expiration timestamp

        Raises:
            ValueError: If required credential claims are missing from token
        """
        # Extract credentials from custom claims configured in IAM Identity Center
        access_key = token_payload.get('aws_access_key_id')
        secret_key = token_payload.get('aws_secret_access_key')
        session_token = token_payload.get('aws_session_token')

        if not (access_key and secret_key and session_token):
            missing = []
            if not access_key:
                missing.append('aws_access_key_id')
            if not secret_key:
                missing.append('aws_secret_access_key')
            if not session_token:
                missing.append('aws_session_token')
            raise ValueError(
                f"JWT token missing required AWS credential claims: {', '.join(missing)}. "
                "Ensure IAM Identity Center application has custom attribute mappings configured."
            )

        logger.debug(f"Successfully extracted AWS credentials from JWT token for account: {token_payload.get('aws_account_id', 'unknown')}")

        return {
            'access_key_id': access_key,
            'secret_access_key': secret_key,
            'session_token': session_token,
            'expiration': token_payload.get('exp'),
            'account_id': token_payload.get('aws_account_id')
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



'''
