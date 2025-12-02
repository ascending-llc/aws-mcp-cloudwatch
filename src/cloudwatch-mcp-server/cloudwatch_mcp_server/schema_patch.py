"""Patch to fix FastMCP's invalid JSON schema generation.

FastMCP generates schemas with two issues:
1. additionalProperties as object instead of boolean (JSON Schema violation)
2. $ref pointers that can't be resolved by Zod validator

This patch fixes both by inlining $defs and converting additionalProperties to boolean.
"""

import logging
from typing import Any, Dict


logger = logging.getLogger('cloudwatch-mcp.schema_patch')


def fix_schema(schema: Dict[str, Any], defs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Fix schema issues in a single pass: inline $refs and fix additionalProperties.

    Args:
        schema: JSON Schema dictionary to fix
        defs: $defs dictionary for resolving references (extracted from root on first call)

    Returns:
        Fixed schema with inlined $defs and boolean additionalProperties
    """
    if not isinstance(schema, dict):
        return schema

    result = schema.copy()

    # First call: extract $defs from root and remove them
    if defs is None:
        defs = result.pop('$defs', {})

    # Inline $ref if present
    if '$ref' in result:
        ref = result['$ref']
        if ref.startswith('#/$defs/'):
            def_name = ref.replace('#/$defs/', '')
            if def_name in defs:
                return fix_schema(defs[def_name].copy(), defs)

    # Fix additionalProperties: object → true
    if 'additionalProperties' in result and isinstance(result['additionalProperties'], dict):
        result['additionalProperties'] = True

    # Recurse into nested schemas
    if 'properties' in result and isinstance(result['properties'], dict):
        result['properties'] = {k: fix_schema(v, defs) for k, v in result['properties'].items()}

    if 'items' in result:
        if isinstance(result['items'], dict):
            result['items'] = fix_schema(result['items'], defs)
        elif isinstance(result['items'], list):
            result['items'] = [fix_schema(item, defs) for item in result['items']]

    for key in ['anyOf', 'allOf', 'oneOf']:
        if key in result and isinstance(result[key], list):
            result[key] = [fix_schema(item, defs) for item in result[key]]

    return result


def patch_fastmcp_schemas(mcp_instance):
    """Patch FastMCP Tool.to_mcp_tool to fix schemas.

    Args:
        mcp_instance: The FastMCP instance to patch (unused, kept for API compatibility)
    """
    # Import Tool class
    try:
        from fastmcp.tools import Tool
    except ImportError:
        try:
            from fastmcp import Tool
        except ImportError:
            logger.error('Could not import Tool class from fastmcp - schema patching disabled')
            return

    # Check if already patched
    if getattr(Tool.to_mcp_tool, '__schema_patched__', False):
        return

    # Store original method
    original_to_mcp_tool = Tool.to_mcp_tool

    def patched_to_mcp_tool(self, **kwargs):
        """Fix schemas before conversion."""
        if hasattr(self, 'parameters') and self.parameters:
            self.parameters = fix_schema(self.parameters)

        if hasattr(self, 'output_schema') and self.output_schema:
            self.output_schema = fix_schema(self.output_schema)

        return original_to_mcp_tool(self, **kwargs)

    # Mark as patched and replace
    patched_to_mcp_tool.__schema_patched__ = True
    Tool.to_mcp_tool = patched_to_mcp_tool

    logger.info('FastMCP schema patching enabled')
