[![soc2-compliance-ai-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/soc2-compliance-ai-mcp/badges/score.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/soc2-compliance-ai-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-Published-green)](https://registry.modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/soc2-compliance-ai-mcp)](https://pypi.org/project/soc2-compliance-ai-mcp/)

[![soc2-compliance-ai-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/soc2-compliance-ai-mcp/badges/card.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/soc2-compliance-ai-mcp)

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/soc2-compliance-ai-mcp)](https://pypi.org/project/soc2-compliance-ai-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/soc2-compliance-ai-mcp)](https://pypi.org/project/soc2-compliance-ai-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/soc2-compliance-ai-mcp)](https://github.com/CSOAI-ORG/soc2-compliance-ai-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# SOC 2 Compliance MCP

**Assess AI/ML systems against all 5 Trust Service Criteria with gap analysis, control matrices, and HMAC-signed attestations.**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing) · [Attestation API](#attestation-api)

</div>

---

## Why This Exists

SOC 2 Type II reports are the baseline trust signal for any SaaS or AI vendor selling into enterprise. But AI systems introduce control gaps that traditional SOC 2 assessments miss: model provenance, training data governance, drift monitoring, and explainability obligations.

Most compliance teams either bolt AI onto existing SOC 2 control matrices by hand or pay $40K+ for a consultancy engagement. This MCP maps AI/ML-specific risks to the 5 Trust Service Criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy), generates control matrices aligned to AICPA 2023 guidance, and crosswalks to ISO 27001 for organisations holding both certifications.

## Install

```bash
pip install soc2-compliance-ai-mcp
```

## Tools

| Tool | TSC Reference | What it does |
|------|--------------|--------------|
| `assess_trust_principles` | CC1-CC9, A1, PI1, C1, P1 | Full assessment against all 5 Trust Service Criteria |
| `control_gap_analysis` | CC6, CC7, CC8 | Identify missing or weak controls for AI systems |
| `generate_control_matrix` | All TSC | Produce a control matrix mapping AI risks to SOC 2 criteria |
| `risk_assessment` | CC3, CC4 | AICPA-aligned risk assessment for AI/ML workloads |
| `crosswalk_to_iso27001` | Annex A mapping | Map SOC 2 controls to ISO 27001:2022 Annex A |
| `readiness_checklist` | Type I / Type II | Pre-audit readiness checklist with remediation priorities |

## Example

```
Prompt: "Assess our customer-facing LLM chatbot against SOC 2 Trust Service
Criteria. It processes financial data, stores conversation logs for 90 days,
and uses a third-party model API."

Result: Assessment across all 5 TSC with findings on third-party model API
vendor risk, missing drift monitoring, undocumented retention policy.
Each finding includes remediation steps and control references.
```

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day — trust principles assessment + gap analysis |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations + verify URLs |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports + webhooks |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

Every Pro/Enterprise audit produces a cryptographically signed certificate:

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

Zero-dep verifier: `pip install meok-attestation-verify`

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT
<!-- mcp-name: io.github.CSOAI-ORG/soc2-compliance-ai-mcp -->
