# SOC 2 Compliance for AI Systems MCP Server

> **By [MEOK AI Labs](https://meok.ai)** -- Sovereign AI tools for everyone.

SOC 2 compliance assessment for AI/ML systems. Assess against all 5 Trust Service Criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy), perform gap analysis, generate control matrices, conduct AICPA risk assessments, crosswalk to ISO 27001, and evaluate Type I/II readiness.

Part of the **CSOAI Governance Suite**: SOC 2 + ISO 27001 + ISO 42001 + GDPR + EU AI Act.

[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `assess_trust_principles` | Audit against 5 Trust Service Criteria with AI extensions |
| `control_gap_analysis` | Gap analysis against SOC 2 controls with remediation plan |
| `generate_control_matrix` | Generate control matrix with evidence requirements |
| `risk_assessment` | SOC 2 risk assessment per AICPA guidelines |
| `crosswalk_to_iso27001` | Map SOC 2 controls to ISO 27001 Annex A |
| `readiness_checklist` | SOC 2 Type I/II readiness assessment with timeline |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/soc2-compliance-ai-mcp.git
cd soc2-compliance-ai-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "soc2-compliance-ai": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/soc2-compliance-ai-mcp"
    }
  }
}
```

## Coverage

- **5 Trust Service Criteria** with all sub-criteria (CC1-CC9, A1, PI1, C1, P1)
- **60+ SOC 2 criteria** with AI-specific extensions
- **13 SOC 2-to-ISO 27001 crosswalk mappings**
- **7 AI-specific risk factors** (model drift, adversarial attacks, prompt injection)
- **Type I and Type II** readiness assessment with timeline and cost estimates

## The US Enterprise Gateway

SOC 2 is the #1 requirement for US enterprise B2B sales. This server provides the bridge between SOC 2 compliance and AI governance, showing how Trust Service Criteria extend to AI-specific risks.

## License

MIT -- see [LICENSE](LICENSE)
