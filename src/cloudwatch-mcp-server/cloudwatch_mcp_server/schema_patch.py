"""Schema patch for FastMCP 2.12.5 bug workaround.

PROBLEM:
--------
FastMCP 2.12.5 generates JSON schemas that violate the JSON Schema specification,
causing validation failures in the MCP SDK's Zod validator. This prevents CloudWatch
MCP tools from appearing in LibreChat.

Two specific issues:

1. Invalid additionalProperties Format
   FastMCP outputs: {"additionalProperties": {"type": "string"}}
   Spec requires: {"additionalProperties": true}

2. Unresolvable $ref Pointers
   FastMCP generates: {"$defs": {...}, "properties": {"$ref": "#/$defs/Foo"}}
   Zod validator cannot resolve these $ref references

THE SOLUTION:
-------------
This module monkey-patches FastMCP's Tool.to_mcp_tool() method to fix schemas
BEFORE they're sent to the MCP SDK client. The fix happens in one recursive pass:

1. Extract $defs from root schema
2. Inline all $ref references (replace pointers with actual definitions)
3. Convert additionalProperties objects to boolean true
4. Recursively process nested schemas

AFFECTED VERSIONS:
------------------
- FastMCP 2.11.3: No bug, works fine
- FastMCP 2.12.5: Has bug, requires this patch
- Only affects streamable-http transport (where Zod validation happens client-side)

WHEN TO REMOVE:
---------------
This patch can be removed once:
1. FastMCP fixes the schema generation bug, AND
2. We upgrade to the fixed FastMCP version

USAGE:
------
The patch is automatically applied when the server starts:
    from cloudwatch_mcp_server.schema_patch import patch_fastmcp_schemas
    patch_fastmcp_schemas(mcp)

SEE ALSO:
---------
- JSON Schema spec: https://json-schema.org/understanding-json-schema/reference/object.html#additional-properties
- Related FastMCP issue: https://github.com/jlowin/fastmcp/issues/2459
"""

import logging
from typing import Any, Dict

logger = logging.getLogger('cloudwatch-mcp.schema_patch')


def fix_schema(schema: Dict[str, Any], defs: Dict[str, Any] = None) -> Dict[str, Any]:
    """Fix schema issues in a single pass: inline $refs and fix additionalProperties.

    This function recursively processes a JSON schema to:
    1. Extract and inline $defs references
    2. Convert invalid additionalProperties objects to boolean true
    3. Process all nested schemas

    Args:
        schema: JSON Schema dictionary to fix
        defs: $defs dictionary for resolving references (extracted from root on first call)

    Returns:
        Fixed schema with inlined $defs and boolean additionalProperties

    Example:
        Before: {"$defs": {"Foo": {...}}, "properties": {"bar": {"$ref": "#/$defs/Foo"}}}
        After:  {"properties": {"bar": {...}}}  # Foo definition inlined
    """
    if not isinstance(schema, dict):
        return schema

    result = schema.copy()

    # STEP 1: Extract $defs from root schema (only happens on first call)
    # This removes the $defs block and stores it for reference resolution
    if defs is None:
        defs = result.pop('$defs', {})

    # STEP 2: Inline $ref if present
    # Replace $ref pointer with the actual definition from $defs
    if '$ref' in result:
        ref = result['$ref']
        if ref.startswith('#/$defs/'):
            # Extract the definition name from the reference
            def_name = ref.replace('#/$defs/', '')
            if def_name in defs:
                # Recursively fix the referenced definition and return it
                # This replaces the entire $ref object with the definition
                return fix_schema(defs[def_name].copy(), defs)

    # STEP 3: Fix additionalProperties format
    # Convert object format to boolean (JSON Schema spec compliance)
    if 'additionalProperties' in result and isinstance(result['additionalProperties'], dict):
        result['additionalProperties'] = True

    # STEP 4: Recursively process nested schemas
    # Handle object properties
    if 'properties' in result and isinstance(result['properties'], dict):
        result['properties'] = {k: fix_schema(v, defs) for k, v in result['properties'].items()}

    # Handle array items
    if 'items' in result:
        if isinstance(result['items'], dict):
            result['items'] = fix_schema(result['items'], defs)
        elif isinstance(result['items'], list):
            result['items'] = [fix_schema(item, defs) for item in result['items']]

    # Handle schema composition keywords (anyOf, allOf, oneOf)
    for key in ['anyOf', 'allOf', 'oneOf']:
        if key in result and isinstance(result[key], list):
            result[key] = [fix_schema(item, defs) for item in result[key]]

    return result


def patch_fastmcp_schemas(mcp_instance):
    """Patch FastMCP Tool.to_mcp_tool to fix schemas before they're sent to clients.

    This function uses monkey-patching to intercept FastMCP's schema generation:

    1. Store reference to original Tool.to_mcp_tool method
    2. Create wrapper function that:
       a. Fixes the tool's parameters schema
       b. Fixes the tool's output_schema
       c. Calls the original method
    3. Replace Tool.to_mcp_tool with our wrapper
    4. Mark as patched to prevent double-patching

    The patching happens once at server startup and affects all tool registrations.

    Flow:
    -----
    Without patch:
        FastMCP Tool → to_mcp_tool() → Invalid Schema → MCP SDK (Zod fails) ❌

    With patch:
        FastMCP Tool → patched_to_mcp_tool() → fix_schema() → Valid Schema → MCP SDK ✓

    Args:
        mcp_instance: The FastMCP instance to patch (unused, kept for API compatibility)
    """
    # Import Tool class from FastMCP
    # Try multiple import paths for compatibility
    try:
        from fastmcp.tools import Tool
    except ImportError:
        try:
            from fastmcp import Tool
        except ImportError:
            logger.error('Could not import Tool class from fastmcp - schema patching disabled')
            return

    # Check if already patched to avoid double-wrapping
    if getattr(Tool.to_mcp_tool, '__schema_patched__', False):
        return

    # Store reference to original method
    original_to_mcp_tool = Tool.to_mcp_tool

    def patched_to_mcp_tool(self, **kwargs):
        """Wrapper that fixes schemas before calling original to_mcp_tool."""
        # Fix input parameters schema
        if hasattr(self, 'parameters') and self.parameters:
            self.parameters = fix_schema(self.parameters)

        # Fix output schema
        if hasattr(self, 'output_schema') and self.output_schema:
            self.output_schema = fix_schema(self.output_schema)

        # Call original method with fixed schemas
        return original_to_mcp_tool(self, **kwargs)

    # Mark the patched method to prevent re-patching
    patched_to_mcp_tool.__schema_patched__ = True

    # Replace the original method with our patched version
    Tool.to_mcp_tool = patched_to_mcp_tool

    logger.info('FastMCP schema patching enabled')
