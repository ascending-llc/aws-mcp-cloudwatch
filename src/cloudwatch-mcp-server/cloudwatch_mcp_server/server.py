import os
from cloudwatch_mcp_server.cloudwatch_alarms.tools import CloudWatchAlarmsTools
from cloudwatch_mcp_server.cloudwatch_logs.tools import CloudWatchLogsTools
from cloudwatch_mcp_server.cloudwatch_metrics.tools import CloudWatchMetricsTools
from cloudwatch_mcp_server.middleware import BrowserCredentialsMiddleware
from fastmcp import FastMCP
from loguru import logger


mcp = FastMCP(
    'cloudwatch-mcp-server',
    instructions='Use this MCP server to run read-only commands and analyze CloudWatch Logs, Metrics, and Alarms. Supports discovering log groups, running CloudWatch Log Insight Queries, retrieving CloudWatch Metrics information, and getting active alarms with region information. With CloudWatch Logs Insights, you can interactively search and analyze your log data. With CloudWatch Metrics, you can get information about system and application metrics. With CloudWatch Alarms, you can retrieve all currently active alarms for operational awareness, with clear indication of which AWS region was checked.',
)

# Add authentication middleware
# Set ENABLE_AUTH=false for local development without authentication
enable_auth = os.getenv('ENABLE_AUTH', 'true').lower() == 'true'

if enable_auth:
    mcp.add_middleware(BrowserCredentialsMiddleware(mcp, enable_auth=True))
    logger.info('Browser credentials authentication enabled')
else:
    logger.info('Authentication disabled; middleware not installed')

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


def main():
    """Run the MCP server."""
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
