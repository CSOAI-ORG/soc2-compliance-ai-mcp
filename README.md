[![MCP Scorecard: 86/100](https://img.shields.io/badge/proofof.ai-86%2F100-5b21b6)](https://proofof.ai/scorecard/soc2-compliance-ai-mcp.html)

# Soc2 Compliance Ai MCP

> **⚖️ Built by [MEOK AI Labs](https://meok.ai) / [CSOAI](https://csoai.org).** Need this applied to _your_ system fast? Book a 30-min Founder Office Hour (£29) → **https://meok.ai/work** · Full governance platform → **https://meok.ai**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://meok.ai)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-22c55e)](https://councilof.ai)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-Install-3775a9)](https://pypi.org/project/soc2_compliance_ai_mcp/)

> SOC 2 Type II compliance MCP — Trust Service Criteria audit, access review, change management, co...
mcp-name: io.github.CSOAI-ORG/soc2-compliance-ai-mcp

<div align="center">

# SOC 2 Compliance MCP

**SOC 2 Trust Service Criteria — Security, Availability, Processing Integrity, Confidentiality, Privacy**

[![MCP](https://img.shields.io/badge/MCP-Server-blue)](https://github.com/CSOAI-ORG)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
</div>

SOC 2 Type II compliance MCP — Trust Service Criteria audit, access review, change management, control evidence automation.

---

## 🚀 Quick Start

```bash
# Install via pip
pip install soc2_compliance_ai_mcp

# Or install via Smithery
npx -y @smithery/cli@latest install soc2-compliance-ai-mcp --client claude
```

## ✨ Features

- MCP protocol compliant
- Easy installation
- Well-documented API
- Production-ready
- Active maintenance

## 📖 Documentation

- [Full Documentation](https://docs.meok.ai/soc2-compliance-ai-mcp)
- [API Reference](https://api.meok.ai)
- [EU AI Act Compliance Guide](https://councilof.ai/compliance)

## 🛡️ Compliance

This MCP server is built with **EU AI Act compliance** built-in:

- ✅ Article 9 — Risk Management System
- ✅ Article 13 — Transparency & Instructions for Use
- ✅ Article 15 — Bias Detection & Testing
- ✅ Article 26 — FRIA Support (where applicable)
- ✅ Article 50 — AI Content Watermarking (where applicable)

Need help getting compliant? **[Book a free 15-min diagnostic →](https://cal.com/csoai/august-audit)**

## 🏢 Enterprise

Need custom development, SLA guarantees, or white-label deployment?

- **Pro:** $99/mo — Full MCP suite + EU AI Act tracking
- **Enterprise:** $499/mo — Custom dev + SLA + Dedicated support

[View Pricing →](https://councilof.ai/pricing) | [Contact Sales →](mailto:sales@csoai.org)

## 🤝 Part of the MEOK Ecosystem

This server is part of the **[MEOK AI Labs](https://meok.ai)** ecosystem — 300+ MCP servers for sovereign AI governance.

| Domain | Purpose |
|--------|---------|
| [councilof.ai](https://councilof.ai) | EU AI Act compliance marketplace |
| [safetyof.ai](https://safetyof.ai) | AI safety & monitoring |
| [meok.ai](https://meok.ai) | Sovereign AI platform |
| [cobolbridge.ai](https://cobolbridge.ai) | Legacy modernization |

## 📜 License

MIT © [CSOAI-ORG](https://github.com/CSOAI-ORG)

---

<p align="center">
  <sub>Built with 💜 by <a href="https://meok.ai">MEOK AI Labs</a> · UK Companies House 16939677</sub>
</p>
AI-powered SOC 2 compliance automation covering all five Trust Service Criteria. Assess controls, generate control matrices, identify gaps, and produce audit-ready documentation.

## Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `assess_trust_principles` | Assess controls against all 5 TSC principles | `principle`, `controls` |
| `control_gap_analysis` | Identify gaps between existing controls and SOC 2 | `current_controls`, `principle` |
| `generate_control_matrix` | Generate a SOC 2 control matrix | `principle`, `controls`, `evidence` |
| `audit_readiness` | Overall SOC 2 audit readiness score | `all_controls`, `principles` |
| `evidence_checklist` | Generate evidence checklist by principle | `principle` (str, required) |
| `remediation_plan` | Prioritized remediation plan for gaps | `findings`, `timeline` |

## Installation

```bash
pip install mcp
```

### Claude Desktop / Cursor / VS Code / Windsurf
```json
{
  "mcpServers": {
    "soc2-compliance": {
      "command": "python",
      "args": ["path/to/server.py"]
    }
  }
}
```

## Usage Examples

### Assess security principle
```json
{
  "principle": "security",
  "controls": ["firewall", "encryption", "access control", "no monitoring"]
}
```

### Generate control matrix
```json
{
  "principle": "availability",
  "controls": ["redundant servers", "backup power", "DR plan"],
  "evidence": ["uptime reports", "DR test results"]
}
```

## Pricing

- **Free:** 10 assessments/day
- **Pro:** $99/mo — unlimited assessments + matrices
- **Enterprise:** $499/mo — full audit trail + readiness scoring

---

*Built by MEOK AI Labs | [meok.ai](https://meok.ai)*

<!-- BUY-LADDER:START -->

## 💸 Try MEOK in 30 seconds — instant buy ladder

| Tier | Price | What you get | Stripe |
|---|---|---|---|
| Smoke test | **£1** | Signed sample MCP-Hardening report + Article 50 PDF | <https://buy.stripe.com/dRmcN75ScdQS7oh1Uc8k90U> |
| Quick Kit | **£9** | EU AI Act Article 50 implementation guide (C2PA + EU-Icon) | <https://buy.stripe.com/cNi00la8s1460ZT0Q88k90V> |
| Founder Call | **£29** | 30-min 1-on-1 with the founder | <https://buy.stripe.com/8x228ta8s6oqbExaqI8k90W> |

> Refundable. UK Stripe — VAT-clean. Builds on the 81-MCP MEOK fleet.
> Verify any signed report at <https://meok.ai/verify>.

<!-- BUY-LADDER:END -->
