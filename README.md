<div align="center">

# Soc2 Compliance Ai MCP

**MCP server for soc2 compliance ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-soc2-compliance-ai-mcp)](https://pypi.org/project/meok-soc2-compliance-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Soc2 Compliance Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `assess_trust_principles` | Audit an AI system against the 5 SOC 2 Trust Service Criteria: Security |
| `control_gap_analysis` | Gap analysis against SOC 2 controls. Compares implemented controls to |
| `generate_control_matrix` | Generate a SOC 2 control matrix with control objectives, criteria, |
| `risk_assessment` | SOC 2 risk assessment per AICPA guidelines. Identifies risks to Trust |
| `crosswalk_to_iso27001` | Map SOC 2 controls to ISO 27001 Annex A controls. Shows how SOC 2 |
| `readiness_checklist` | SOC 2 Type I/II readiness assessment. Generates a comprehensive |

## Installation

```bash
pip install meok-soc2-compliance-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "soc2-compliance-ai-mcp": {
      "command": "python",
      "args": ["-m", "meok_soc2_compliance_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 6 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
