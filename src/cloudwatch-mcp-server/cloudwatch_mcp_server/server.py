import os
from cloudwatch_mcp_server.cloudwatch_alarms.tools import CloudWatchAlarmsTools
from cloudwatch_mcp_server.cloudwatch_logs.tools import CloudWatchLogsTools
from cloudwatch_mcp_server.cloudwatch_metrics.tools import CloudWatchMetricsTools
from fastmcp import FastMCP
from loguru import logger


# Authentication middleware archived in _future_auth/ - not currently used
# Production uses IRSA (IAM Roles for Service Accounts) for AWS authentication

mcp = FastMCP(
    'cloudwatch-mcp-server',
    instructions='Use this MCP server to run read-only commands and analyze CloudWatch Logs, Metrics, and Alarms. Supports discovering log groups, running CloudWatch Log Insight Queries, retrieving CloudWatch Metrics information, and getting active alarms with region information. With CloudWatch Logs Insights, you can interactively search and analyze your log data. With CloudWatch Metrics, you can get information about system and application metrics. With CloudWatch Alarms, you can retrieve all currently active alarms for operational awareness, with clear indication of which AWS region was checked.',
)

# Apply schema patch to work around FastMCP bug where additionalProperties
# is generated as an object instead of a boolean
# See: https://github.com/jlowin/fastmcp/issues/2459
from cloudwatch_mcp_server.schema_patch import patch_fastmcp_schemas


patch_fastmcp_schemas(mcp)
logger.info('Applied FastMCP schema patch for additionalProperties')

# Initialize and register CloudWatch tools
try:
    cloudwatch_logs_tools = CloudWatchLogsTools()
    cloudwatch_logs_tools.register(mcp)
    logger.info('CloudWatch Logs tools registered successfully')
    cloudwatch_metrics_tools = CloudWatchMetricsTools()
    cloudwatch_metrics_tools.register(mcp)
    logger.info('CloudWatch Metrics tools registered successfully')
    cloudwatch_alarms_tools = CloudWatchAlarmsTools()
    cloudwatch_alarms_tools.register(mcp)
    logger.info('CloudWatch Alarms tools registered successfully')
except Exception as e:
    logger.error(f'Error initializing CloudWatch tools: {str(e)}')
    raise


"""Run the MCP server."""


# Add health check endpoint for Kubernetes/monitoring probes
from starlette.requests import Request
from starlette.responses import JSONResponse


@mcp.custom_route('/health', methods=['GET'], include_in_schema=False)
async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse({'status': 'ok'})


logger.info('Added /health endpoint')


def main():
    logger.info('Initializing CloudWatch MCP server...')
    logger.info('AWS_PROFILE=%s  AWS_REGION=%s', os.getenv('AWS_PROFILE'), os.getenv('AWS_REGION'))
    host = os.getenv('CLOUDWATCH_MCP_SERVER_HOST', '0.0.0.0')
    raw_port = os.getenv('CLOUDWATCH_MCP_PORT', '3334')

    try:
        port = int(raw_port)
    except ValueError:
        if raw_port.startswith('tcp://') and ':' in raw_port:
            port = int(raw_port.rsplit(':', 1)[-1])
            logger.warning('Normalized CLOUDWATCH_MCP_PORT %s to %s', raw_port, port)
        else:
            logger.warning('Invalid CLOUDWATCH_MCP_PORT %s, defaulting to 3334', raw_port)
            port = 3334

    mcp.run(transport='streamable-http', host=host, port=port)

    logger.info('CloudWatch MCP server started')


if __name__ == '__main__':
    main()
