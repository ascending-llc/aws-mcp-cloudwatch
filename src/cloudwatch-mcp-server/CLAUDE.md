# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is the CloudWatch MCP Server, part of the AWS Labs MCP monorepo. It provides AI agents with access to CloudWatch telemetry data through standardized MCP interfaces for alarm troubleshooting, log analysis, and metrics inspection.

## Project Structure

The codebase follows a modular, domain-driven architecture:

```
cloudwatch_mcp_server/
├── server.py                    # Main entry point, MCP server initialization
├── common.py                    # Shared utilities (time conversion, filtering, etc.)
├── cloudwatch_alarms/
│   ├── models.py               # Pydantic models for alarm data
│   └── tools.py                # Alarm-related MCP tools (get_active_alarms, get_alarm_history)
├── cloudwatch_logs/
│   ├── models.py               # Pydantic models for log data
│   └── tools.py                # Log-related MCP tools (analyze_log_group, execute queries, etc.)
└── cloudwatch_metrics/
    ├── models.py               # Pydantic models for metric data
    ├── tools.py                # Metrics-related MCP tools (get_metric_data, get_metadata, etc.)
    └── data/
        └── metric_metadata.json # Pre-loaded metadata for CloudWatch metrics
```

### Architecture Pattern

Each CloudWatch domain (alarms, logs, metrics) is organized as:
- **tools.py**: Contains a class (e.g., `CloudWatchAlarmsTools`) that encapsulates all MCP tools for that domain
- **models.py**: Defines Pydantic models for request/response validation
- **register() method**: Each tools class has a `register(mcp)` method that registers tools with the FastMCP server

The main `server.py` initializes all tool classes and registers them with the FastMCP instance.

## Common Development Commands

### Testing
```bash
# Run all tests with coverage
uv run --frozen pytest --cov --cov-branch --cov-report=term-missing

# Run tests for a specific module
uv run --frozen pytest tests/cloudwatch_alarms/
uv run --frozen pytest tests/cloudwatch_logs/
uv run --frozen pytest tests/cloudwatch_metrics/

# Run a single test file
uv run --frozen pytest tests/cloudwatch_alarms/test_active_alarms.py

# Run tests excluding live API calls
uv run --frozen pytest -m "not live"
```

### Linting and Formatting
```bash
# Run ruff linting (from project root or server directory)
uv run ruff check .

# Auto-fix linting issues
uv run ruff check --fix .

# Format code
uv run ruff format .

# Type checking with pyright
uv run pyright
```

### Running the Server

#### Locally via stdio (for MCP clients)
```bash
uv run --directory /path/to/src/cloudwatch-mcp-server server.py
```

#### Locally via HTTP (for testing)
```bash
# Set environment variables
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
export FASTMCP_LOG_LEVEL=INFO

# Run the server
uv run server.py
```

#### Using MCP Inspector (for debugging)
```bash
npx @modelcontextprotocol/inspector \
  uv \
  --directory /path/to/src/cloudwatch-mcp-server \
  run \
  server.py
```

### Environment Setup
```bash
# Create virtual environment and install dependencies
uv venv && uv sync --all-groups

# Install pre-commit hooks (run from monorepo root)
pre-commit install
```

## Key Implementation Patterns

### AWS Client Initialization
Each tools class creates boto3 clients with:
- User agent string including MCP server version from `MCP_SERVER_VERSION` constant
- Support for both `AWS_PROFILE` and default credentials
- Region-specific client creation via `_get_cloudwatch_client()` or `_get_logs_client()` methods

### Tool Registration Pattern
```python
def register(self, mcp):
    """Register all tools with the MCP server."""
    mcp.tool(name='tool_name')(self.tool_method)
```

### Error Handling
- Use `ctx.error()` for MCP context-aware error reporting
- Log errors with `loguru.logger` before raising
- Validate input parameters early in tool methods

### Response Formatting
- Return Pydantic models for structured responses
- Use `json.dumps()` for serializing complex nested data
- Include helpful metadata (region, timestamps, etc.) in responses

### Asynchronous Operations
- All MCP tool methods are async: `async def tool_name(self, ctx: Context, ...)`
- Use `asyncio.gather()` for concurrent AWS API calls when appropriate
- Handle pagination with boto3 paginators

## CloudWatch-Specific Implementation Details

### Logs Tools
- **Query Execution**: Uses CloudWatch Logs Insights with `start_query` → poll `get_query_results`
- **Log Analysis**: Combines anomaly detection, pattern matching, and error analysis
- **Time Handling**: Converts ISO 8601 strings to Unix epoch milliseconds for AWS APIs

### Metrics Tools
- **Metadata**: Pre-loaded from `metric_metadata.json` and indexed by namespace/metric name
- **Metric Data Retrieval**: Uses `get_metric_data` API with MetricDataQuery format
- **Alarm Recommendations**: Provides threshold suggestions based on metric metadata

### Alarms Tools
- **Active Alarms**: Fetches alarms in ALARM state, separates metric vs composite alarms
- **History**: Retrieves alarm state transitions with configurable lookback periods
- **Composite Alarm Resolution**: Recursively resolves child alarms for composite alarms

## Design Guidelines Compliance

This server follows the [DESIGN_GUIDELINES.md](../../../DESIGN_GUIDELINES.md) from the monorepo:

- **Apache 2.0 license headers** on all Python files
- **Pydantic models** for all data validation with detailed Field descriptions
- **Loguru logging** configured via `FASTMCP_LOG_LEVEL` environment variable
- **AWS authentication** via boto3 with profile/region support
- **Tool naming**: Uses descriptive snake_case names (e.g., `get_active_alarms`)
- **Docstrings**: Google-style docstrings with Args, Returns, and Examples
- **Entry point**: Single main() function in server.py
- **Versioning**: Stored in `__init__.py` as `MCP_SERVER_VERSION`

## Testing Considerations

- **Mock AWS Services**: Use `moto` for mocking boto3 clients in unit tests
- **Live Tests**: Mark with `@pytest.mark.live` for tests that require real AWS credentials
- **Async Tests**: Use `pytest-asyncio` with `asyncio_mode = "auto"` in pytest.ini
- **Coverage Targets**: Match or exceed the monorepo coverage badge (visible in main README)

## Important Notes

### Token Usage Management
CloudWatch responses can be large (especially log queries). The codebase includes:
- `clean_up_pattern()` in `common.py` to reduce token usage from pattern queries
- `max_items` parameters with defaults to limit response sizes
- Warnings in tool descriptions about context window overflow with large values

### Version Synchronization
- Version is defined in both `pyproject.toml` and `__init__.py`
- The monorepo's `release.py` script bumps versions automatically
- Update `CHANGELOG.md` when making changes

### Conventional Commits
Use conventional commit messages (enforced by pre-commit):
- `feat:` for new features
- `fix:` for bug fixes
- `chore:` for maintenance
- `docs:` for documentation
- Scope with module name: `feat(alarms): add composite alarm support`

## Common Pitfalls

1. **Forgetting to register tools**: New tools must be added to the `register()` method
2. **Missing AWS client config**: Always include user agent with MCP_SERVER_VERSION
3. **Not handling pagination**: Large CloudWatch responses require proper pagination
4. **Ignoring time zones**: CloudWatch uses Unix epoch milliseconds; convert properly
5. **Incomplete Pydantic models**: All optional fields should use `Optional[Type]` and have defaults

## Related Documentation

- [README.md](./README.md) - Installation and usage instructions
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Docker, OAuth, and CI/CD deployment guide
- [DEVELOPER_GUIDE.md](../../../DEVELOPER_GUIDE.md) - Setup and contribution workflow
- [DESIGN_GUIDELINES.md](../../../DESIGN_GUIDELINES.md) - MCP server design patterns
- [CloudWatch Documentation](https://docs.aws.amazon.com/cloudwatch/) - AWS service reference
