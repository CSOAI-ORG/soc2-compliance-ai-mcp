#!/usr/bin/env python3
"""
SOC 2 Compliance for AI Systems MCP Server
============================================
By MEOK AI Labs | https://meok.ai

SOC 2 (Service Organization Controls 2) compliance assessment for AI/ML
systems. Covers all 5 Trust Service Criteria (Security, Availability,
Processing Integrity, Confidentiality, Privacy), control gap analysis,
control matrix generation, risk assessment per AICPA guidelines, ISO 27001
crosswalks, and Type I/II readiness assessment.

Reference: AICPA Trust Service Criteria (2017), AT-C Section 205,
           SOC 2 Reporting on Controls at a Service Organization

Install: pip install mcp
Run:     python server.py
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)


def _check_rate_limit(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit reached ({FREE_DAILY_LIMIT}/day). "
            "Upgrade to MEOK AI Labs Pro for unlimited: https://meok.ai/mcp/soc2-compliance-ai/pro"
        )
    _usage[caller].append(now)
    return None


# ---------------------------------------------------------------------------
# FastMCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "soc2-compliance-ai",
    instructions=(
        "SOC 2 Compliance for AI Systems server. Assess AI systems against all "
        "5 Trust Service Criteria (Security, Availability, Processing Integrity, "
        "Confidentiality, Privacy), perform control gap analysis, generate control "
        "matrices with evidence requirements, conduct AICPA risk assessments, "
        "crosswalk to ISO 27001, and evaluate Type I/II readiness. By MEOK AI Labs."
    ),
)

# ---------------------------------------------------------------------------
# SOC 2 Trust Service Criteria — All 5 Principles with Point of Focus
# ---------------------------------------------------------------------------

TRUST_SERVICE_CRITERIA = {
    "CC": {
        "name": "Common Criteria (Security)",
        "description": "Information and systems are protected against unauthorized access, unauthorized disclosure of information, and damage to systems that could compromise the availability, integrity, confidentiality, and privacy of information or systems.",
        "series": {
            "CC1": {
                "title": "Control Environment",
                "criteria": {
                    "CC1.1": "The entity demonstrates a commitment to integrity and ethical values.",
                    "CC1.2": "The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control.",
                    "CC1.3": "Management establishes, with board oversight, structures, reporting lines, and appropriate authorities and responsibilities in the pursuit of objectives.",
                    "CC1.4": "The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives.",
                    "CC1.5": "The entity holds individuals accountable for their internal control responsibilities in the pursuit of objectives.",
                },
                "ai_extensions": "AI governance board or committee, AI ethics officer role, AI-specific accountability frameworks.",
            },
            "CC2": {
                "title": "Communication and Information",
                "criteria": {
                    "CC2.1": "The entity obtains or generates and uses relevant, quality information to support the functioning of internal control.",
                    "CC2.2": "The entity internally communicates information, including objectives and responsibilities for internal control, necessary to support the functioning of internal control.",
                    "CC2.3": "The entity communicates with external parties regarding matters affecting the functioning of internal control.",
                },
                "ai_extensions": "AI system documentation, model cards, training data documentation, AI incident communication protocols.",
            },
            "CC3": {
                "title": "Risk Assessment",
                "criteria": {
                    "CC3.1": "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives.",
                    "CC3.2": "The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed.",
                    "CC3.3": "The entity considers the potential for fraud in assessing risks to the achievement of objectives.",
                    "CC3.4": "The entity identifies and assesses changes that could significantly impact the system of internal control.",
                },
                "ai_extensions": "AI-specific risk register, model risk management, adversarial risk assessment, data drift monitoring.",
            },
            "CC4": {
                "title": "Monitoring Activities",
                "criteria": {
                    "CC4.1": "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.",
                    "CC4.2": "The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action, including senior management and the board of directors, as appropriate.",
                },
                "ai_extensions": "Continuous AI model monitoring, bias detection dashboards, performance drift alerts, automated compliance checks.",
            },
            "CC5": {
                "title": "Control Activities",
                "criteria": {
                    "CC5.1": "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.",
                    "CC5.2": "The entity also selects and develops general control activities over technology to support the achievement of objectives.",
                    "CC5.3": "The entity deploys control activities through policies that establish what is expected and in procedures that put policies into action.",
                },
                "ai_extensions": "AI access controls, model deployment gates, automated testing pipelines, AI change management procedures.",
            },
            "CC6": {
                "title": "Logical and Physical Access Controls",
                "criteria": {
                    "CC6.1": "The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
                    "CC6.2": "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
                    "CC6.3": "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets.",
                    "CC6.4": "The entity restricts physical access to facilities and protected information assets.",
                    "CC6.5": "The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished.",
                    "CC6.6": "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
                    "CC6.7": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
                    "CC6.8": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
                },
                "ai_extensions": "Model access controls, training data access management, API authentication for AI services, model artifact protection.",
            },
            "CC7": {
                "title": "System Operations",
                "criteria": {
                    "CC7.1": "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
                    "CC7.2": "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.",
                    "CC7.3": "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives and, if so, takes action to prevent or address such failures.",
                    "CC7.4": "The entity responds to identified security incidents by executing a defined incident response program.",
                    "CC7.5": "The entity identifies, develops, and implements activities to recover from identified security incidents.",
                },
                "ai_extensions": "AI model monitoring for drift and adversarial inputs, AI incident response plans, model rollback procedures.",
            },
            "CC8": {
                "title": "Change Management",
                "criteria": {
                    "CC8.1": "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
                },
                "ai_extensions": "ML model versioning, model deployment approvals, A/B testing governance, dataset change tracking.",
            },
            "CC9": {
                "title": "Risk Mitigation",
                "criteria": {
                    "CC9.1": "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
                    "CC9.2": "The entity assesses and manages risks associated with vendors and business partners.",
                },
                "ai_extensions": "AI vendor risk assessment (model providers, data providers), AI business continuity planning.",
            },
        },
    },
    "A": {
        "name": "Availability",
        "description": "Information and systems are available for operation and use to meet the entity's objectives.",
        "series": {
            "A1": {
                "title": "Availability Criteria",
                "criteria": {
                    "A1.1": "The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand and to enable the implementation of additional capacity to help meet its objectives.",
                    "A1.2": "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup, and recovery infrastructure and processes to meet its objectives.",
                    "A1.3": "The entity tests recovery plan procedures supporting system recovery to meet its objectives.",
                },
                "ai_extensions": "GPU/TPU capacity planning, model serving scalability, AI inference SLA monitoring, model fallback procedures.",
            },
        },
    },
    "PI": {
        "name": "Processing Integrity",
        "description": "System processing is complete, valid, accurate, timely, and authorized to meet the entity's objectives.",
        "series": {
            "PI1": {
                "title": "Processing Integrity Criteria",
                "criteria": {
                    "PI1.1": "The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives related to processing, including definitions of data processed and product and service specifications.",
                    "PI1.2": "The entity implements policies and procedures over system inputs, including controls over completeness and accuracy.",
                    "PI1.3": "The entity implements policies and procedures over system processing to ensure that processing is complete, valid, accurate, timely, and authorized.",
                    "PI1.4": "The entity implements policies and procedures to make available or deliver output completely, accurately, and timely in accordance with specifications.",
                    "PI1.5": "The entity implements policies and procedures to store inputs, items in processing, and outputs completely, accurately, and timely.",
                },
                "ai_extensions": "AI model validation, input data quality checks, output accuracy monitoring, inference latency SLAs, AI decision audit trails.",
            },
        },
    },
    "C": {
        "name": "Confidentiality",
        "description": "Information designated as confidential is protected to meet the entity's objectives.",
        "series": {
            "C1": {
                "title": "Confidentiality Criteria",
                "criteria": {
                    "C1.1": "The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.",
                    "C1.2": "The entity disposes of confidential information to meet the entity's objectives related to confidentiality.",
                },
                "ai_extensions": "Model confidentiality (trade secret protection), training data confidentiality, inference data handling, model extraction prevention.",
            },
        },
    },
    "P": {
        "name": "Privacy",
        "description": "Personal information is collected, used, retained, disclosed, and disposed of to meet the entity's objectives.",
        "series": {
            "P1": {
                "title": "Privacy Criteria",
                "criteria": {
                    "P1.1": "The entity provides notice to data subjects about its privacy practices.",
                    "P1.2": "The entity communicates choices available regarding the collection, use, retention, disclosure, and disposal of personal information.",
                    "P2.1": "The entity collects personal information for the purposes identified in the notice.",
                    "P3.1": "The entity collects personal information only for the purposes identified in its notice.",
                    "P3.2": "The entity creates, maintains, and uses personal information relevant to the purposes identified in the notice.",
                    "P4.1": "The entity limits the use of personal information to the purposes identified in the notice.",
                    "P4.2": "The entity retains personal information for the time necessary to fulfill the purposes identified in the notice.",
                    "P4.3": "The entity securely disposes of personal information when the purposes identified in the notice are no longer being served.",
                    "P5.1": "The entity grants identified and authenticated data subjects the ability to access their stored personal information for review.",
                    "P5.2": "The entity corrects, amends, or appends personal information based on information provided by data subjects.",
                    "P6.1": "The entity discloses personal information to third parties with the consent of the data subject.",
                    "P6.2": "The entity creates and retains a complete, accurate, and timely record of authorized disclosures of personal information.",
                    "P6.3": "The entity creates and retains a complete, accurate, and timely record of detected or reported unauthorized disclosures of personal information.",
                    "P6.4": "The entity obtains privacy commitments from vendors and other third parties.",
                    "P6.5": "The entity obtains commitments from vendors and other third parties with access to personal information to notify the entity in the event of actual or suspected unauthorized disclosures.",
                    "P7.1": "The entity collects and maintains accurate, up-to-date, complete, and relevant personal information for the purposes identified in the notice.",
                    "P8.1": "The entity implements a process for receiving, addressing, resolving, and communicating the resolution of inquiries, complaints, and disputes from data subjects.",
                },
                "ai_extensions": "AI training data collection notice, AI inference data handling, model memorization controls, AI privacy impact assessments.",
            },
        },
    },
}

# ---------------------------------------------------------------------------
# SOC 2 to ISO 27001 Crosswalk
# ---------------------------------------------------------------------------

SOC2_ISO27001_CROSSWALK = {
    "CC1": {"iso27001": ["A.5.1", "A.5.2", "A.5.4", "A.5.36"], "note": "Control environment maps to organizational policies and management responsibilities."},
    "CC2": {"iso27001": ["A.5.37", "A.5.5", "A.5.6"], "note": "Communication and information maps to documented procedures and external contacts."},
    "CC3": {"iso27001": ["A.5.7", "A.5.8"], "note": "Risk assessment maps to threat intelligence and project security."},
    "CC4": {"iso27001": ["A.5.35", "A.5.36"], "note": "Monitoring maps to independent review and compliance checking."},
    "CC5": {"iso27001": ["A.5.10", "A.5.37", "A.8.9"], "note": "Control activities map to acceptable use, procedures, and configuration management."},
    "CC6": {"iso27001": ["A.5.15", "A.5.16", "A.5.17", "A.5.18", "A.7.1", "A.7.2", "A.8.1", "A.8.2", "A.8.3", "A.8.5"], "note": "Access controls map directly to ISO 27001 access management controls."},
    "CC7": {"iso27001": ["A.5.24", "A.5.25", "A.5.26", "A.5.27", "A.8.8", "A.8.15", "A.8.16"], "note": "System operations map to incident management and monitoring."},
    "CC8": {"iso27001": ["A.8.25", "A.8.29", "A.8.31", "A.8.32"], "note": "Change management maps to SDLC, testing, and change controls."},
    "CC9": {"iso27001": ["A.5.19", "A.5.29", "A.5.30"], "note": "Risk mitigation maps to supplier security and business continuity."},
    "A1": {"iso27001": ["A.7.11", "A.8.6", "A.8.13", "A.8.14"], "note": "Availability maps to utilities, capacity, backup, and redundancy."},
    "PI1": {"iso27001": ["A.8.9", "A.8.25", "A.8.26", "A.8.33"], "note": "Processing integrity maps to configuration, SDLC, and testing."},
    "C1": {"iso27001": ["A.5.12", "A.5.13", "A.5.14", "A.8.10", "A.8.11", "A.8.24"], "note": "Confidentiality maps to classification, labelling, transfer, deletion, masking, and cryptography."},
    "P1": {"iso27001": ["A.5.34"], "note": "Privacy criteria maps to ISO 27001 PII protection control. For full privacy mapping, reference ISO 27701."},
}


# ---------------------------------------------------------------------------
# TOOL 1: Assess Trust Principles
# ---------------------------------------------------------------------------
@mcp.tool()
def assess_trust_principles(
    system_description: str,
    principles_in_scope: Optional[list[str]] = None,
    controls_implemented: Optional[dict[str, list[str]]] = None,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Audit an AI system against the 5 SOC 2 Trust Service Criteria: Security
    (Common Criteria), Availability, Processing Integrity, Confidentiality,
    and Privacy. Returns compliance status per principle with AI-specific findings.

    Args:
        system_description: Description of the AI system or service being assessed
        principles_in_scope: Which principles to assess (default all 5): ["CC", "A", "PI", "C", "P"]
        controls_implemented: Dict mapping criteria series to implemented controls, e.g. {"CC6": ["CC6.1", "CC6.2"]}
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    scope = principles_in_scope or ["CC", "A", "PI", "C", "P"]
    implemented = controls_implemented or {}

    results = {
        "assessment_type": "SOC 2 Trust Service Criteria Assessment",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system_description,
        "principles_assessed": [],
        "summary": {},
    }

    total_criteria = 0
    total_met = 0

    for principle_key in scope:
        if principle_key not in TRUST_SERVICE_CRITERIA:
            continue
        principle = TRUST_SERVICE_CRITERIA[principle_key]
        principle_result = {
            "principle": principle["name"],
            "description": principle["description"],
            "series_results": [],
            "total_criteria": 0,
            "criteria_met": 0,
        }

        for series_key, series_data in principle["series"].items():
            series_implemented = set(implemented.get(series_key, []))
            criteria_list = series_data["criteria"]
            met = [c for c in criteria_list if c in series_implemented]
            gaps = [{"id": c, "requirement": criteria_list[c]} for c in criteria_list if c not in series_implemented]

            principle_result["total_criteria"] += len(criteria_list)
            principle_result["criteria_met"] += len(met)
            total_criteria += len(criteria_list)
            total_met += len(met)

            coverage = (len(met) / len(criteria_list) * 100) if criteria_list else 0
            principle_result["series_results"].append({
                "series": series_key,
                "title": series_data["title"],
                "criteria_count": len(criteria_list),
                "met": len(met),
                "gaps": gaps[:5],
                "coverage_percent": round(coverage, 1),
                "ai_extensions": series_data["ai_extensions"],
            })

        p_coverage = (principle_result["criteria_met"] / principle_result["total_criteria"] * 100) if principle_result["total_criteria"] else 0
        principle_result["coverage_percent"] = round(p_coverage, 1)
        principle_result["status"] = "PASS" if p_coverage >= 80 else "PARTIAL" if p_coverage >= 50 else "FAIL"
        results["principles_assessed"].append(principle_result)

    overall = (total_met / total_criteria * 100) if total_criteria else 0
    results["summary"] = {
        "total_criteria": total_criteria,
        "criteria_met": total_met,
        "overall_coverage_percent": round(overall, 1),
        "soc2_ready": overall >= 85,
        "recommendation": (
            "System meets SOC 2 readiness threshold. Proceed with auditor engagement."
            if overall >= 85
            else f"Address gaps before SOC 2 audit. Current coverage: {round(overall, 1)}%."
        ),
    }

    return json.dumps(results, indent=2)


# ---------------------------------------------------------------------------
# TOOL 2: Control Gap Analysis
# ---------------------------------------------------------------------------
@mcp.tool()
def control_gap_analysis(
    implemented_controls: list[str],
    target_type: str = "type2",
    principles_in_scope: Optional[list[str]] = None,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Gap analysis against SOC 2 controls. Compares implemented controls to
    required criteria and produces a prioritized remediation plan.

    Args:
        implemented_controls: List of implemented SOC 2 criteria IDs (e.g. ["CC1.1", "CC6.1", "A1.1"])
        target_type: "type1" (point-in-time) or "type2" (period of time, requires operational evidence)
        principles_in_scope: Filter to specific principles ["CC", "A", "PI", "C", "P"]
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    implemented = set(implemented_controls)
    scope = principles_in_scope or ["CC", "A", "PI", "C", "P"]

    results = {
        "analysis_type": f"SOC 2 {target_type.upper()} Control Gap Analysis",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "gaps_by_principle": {},
        "remediation_plan": [],
        "summary": {},
    }

    all_gaps = []
    total_required = 0
    total_met = 0

    # CC (Security) is always required for SOC 2
    critical_series = {"CC1", "CC2", "CC3", "CC5", "CC6", "CC7"}

    for principle_key in scope:
        if principle_key not in TRUST_SERVICE_CRITERIA:
            continue
        principle = TRUST_SERVICE_CRITERIA[principle_key]
        principle_gaps = []

        for series_key, series_data in principle["series"].items():
            for criteria_id, criteria_desc in series_data["criteria"].items():
                total_required += 1
                if criteria_id in implemented:
                    total_met += 1
                else:
                    priority = "critical" if series_key in critical_series else "high" if principle_key == "CC" else "medium"
                    gap = {
                        "criteria_id": criteria_id,
                        "series": series_key,
                        "title": series_data["title"],
                        "requirement": criteria_desc,
                        "priority": priority,
                        "principle": principle["name"],
                    }
                    principle_gaps.append(gap)
                    all_gaps.append(gap)

        results["gaps_by_principle"][principle_key] = {
            "principle": principle["name"],
            "gaps": principle_gaps,
            "gap_count": len(principle_gaps),
        }

    # Prioritized remediation
    priority_order = {"critical": 0, "high": 1, "medium": 2}
    all_gaps.sort(key=lambda g: (priority_order.get(g["priority"], 3), g["criteria_id"]))

    results["remediation_plan"] = [
        {"phase": "Phase 1 — Critical Controls (Weeks 1-4)", "controls": [g for g in all_gaps if g["priority"] == "critical"]},
        {"phase": "Phase 2 — High Priority (Weeks 5-8)", "controls": [g for g in all_gaps if g["priority"] == "high"]},
        {"phase": "Phase 3 — Medium Priority (Weeks 9-12)", "controls": [g for g in all_gaps if g["priority"] == "medium"]},
    ]

    if target_type == "type2":
        results["type2_additional_requirements"] = {
            "observation_period": "Minimum 6 months, typically 12 months",
            "evidence_collection": "Must demonstrate controls operated effectively over the period",
            "key_evidence": [
                "Access review logs covering the observation period",
                "Change management records for all system changes",
                "Incident response records and resolution documentation",
                "Security awareness training completion records",
                "Vulnerability scan and penetration test results",
                "Backup and recovery test results",
                "Vendor risk assessment documentation",
            ],
        }

    coverage = (total_met / total_required * 100) if total_required else 0
    results["summary"] = {
        "total_required": total_required,
        "total_met": total_met,
        "total_gaps": len(all_gaps),
        "coverage_percent": round(coverage, 1),
        "critical_gaps": len([g for g in all_gaps if g["priority"] == "critical"]),
        "estimated_weeks": 12 if len(all_gaps) > 20 else 8 if len(all_gaps) > 10 else 4,
        "readiness": "Ready" if coverage >= 90 else "Near-ready" if coverage >= 75 else "Significant work needed",
    }

    return json.dumps(results, indent=2)


# ---------------------------------------------------------------------------
# TOOL 3: Generate Control Matrix
# ---------------------------------------------------------------------------
@mcp.tool()
def generate_control_matrix(
    organization_name: str,
    principles_in_scope: Optional[list[str]] = None,
    include_evidence: bool = True,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Generate a SOC 2 control matrix with control objectives, criteria,
    control activities, and evidence requirements. Suitable for auditor
    preparation and internal control documentation.

    Args:
        organization_name: Name of the organization
        principles_in_scope: Which principles to include (default all 5)
        include_evidence: Whether to include detailed evidence requirements
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    scope = principles_in_scope or ["CC", "A", "PI", "C", "P"]

    evidence_map = {
        "CC1": ["Board meeting minutes", "Code of conduct", "Organizational chart", "HR policies", "Performance evaluations"],
        "CC2": ["Information security policy", "Communication procedures", "External reporting records", "System documentation"],
        "CC3": ["Risk assessment documentation", "Risk register", "Fraud risk assessment", "Change impact assessments"],
        "CC4": ["Internal audit reports", "Monitoring tool outputs", "Deficiency tracking log", "Management review minutes"],
        "CC5": ["Control activity documentation", "Policy documents", "Procedure manuals", "Technology standards"],
        "CC6": ["Access control lists", "User provisioning records", "Physical access logs", "Firewall configurations", "Encryption certificates"],
        "CC7": ["Vulnerability scan results", "IDS/IPS logs", "Incident response records", "Recovery test results"],
        "CC8": ["Change management records", "Test results", "Deployment approvals", "Rollback procedures"],
        "CC9": ["Business continuity plans", "Vendor assessments", "Insurance policies", "Disaster recovery tests"],
        "A1": ["Uptime monitoring reports", "Capacity planning documents", "Backup test results", "DR test results"],
        "PI1": ["Input validation rules", "Processing logs", "Output verification records", "Data quality reports"],
        "C1": ["Data classification scheme", "Encryption standards", "Data disposal records", "Confidentiality agreements"],
        "P1": ["Privacy notice", "Consent records", "Data subject request logs", "Privacy impact assessments", "Vendor privacy commitments"],
    }

    matrix = {
        "document_type": "SOC 2 Control Matrix",
        "organization": organization_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "principles": [],
    }

    for principle_key in scope:
        if principle_key not in TRUST_SERVICE_CRITERIA:
            continue
        principle = TRUST_SERVICE_CRITERIA[principle_key]
        principle_entry = {
            "principle": principle["name"],
            "description": principle["description"],
            "control_series": [],
        }

        for series_key, series_data in principle["series"].items():
            series_entry = {
                "series_id": series_key,
                "title": series_data["title"],
                "criteria": [],
                "ai_extensions": series_data["ai_extensions"],
            }
            if include_evidence:
                series_entry["evidence_requirements"] = evidence_map.get(series_key, ["Documentation to be determined"])

            for criteria_id, criteria_desc in series_data["criteria"].items():
                series_entry["criteria"].append({
                    "id": criteria_id,
                    "requirement": criteria_desc,
                    "control_activity": f"[To be documented by {organization_name}]",
                    "control_owner": "[To be assigned]",
                    "frequency": "Continuous" if "monitor" in criteria_desc.lower() else "Periodic",
                    "type": "Preventive" if any(w in criteria_desc.lower() for w in ["restrict", "protect", "prevent"]) else "Detective",
                })

            principle_entry["control_series"].append(series_entry)

        matrix["principles"].append(principle_entry)

    return json.dumps(matrix, indent=2)


# ---------------------------------------------------------------------------
# TOOL 4: Risk Assessment
# ---------------------------------------------------------------------------
@mcp.tool()
def risk_assessment(
    system_description: str,
    service_commitments: list[str],
    known_risks: Optional[list[str]] = None,
    ai_specific: bool = True,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """SOC 2 risk assessment per AICPA guidelines. Identifies risks to Trust
    Service Criteria, assesses likelihood and impact, and maps to specific
    SOC 2 control requirements.

    Args:
        system_description: Description of the service organization and its systems
        service_commitments: System Description service commitments (SLAs, security guarantees)
        known_risks: Already identified risks to evaluate
        ai_specific: Whether to include AI-specific risk factors
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    standard_risks = [
        {"risk": "Unauthorized access to systems or data", "principle": "CC", "series": "CC6", "likelihood": "high", "impact": "high"},
        {"risk": "System or service unavailability", "principle": "A", "series": "A1", "likelihood": "medium", "impact": "high"},
        {"risk": "Inaccurate or incomplete data processing", "principle": "PI", "series": "PI1", "likelihood": "medium", "impact": "high"},
        {"risk": "Unauthorized disclosure of confidential information", "principle": "C", "series": "C1", "likelihood": "medium", "impact": "high"},
        {"risk": "Failure to protect personal information", "principle": "P", "series": "P1", "likelihood": "medium", "impact": "high"},
        {"risk": "Inadequate change management", "principle": "CC", "series": "CC8", "likelihood": "medium", "impact": "medium"},
        {"risk": "Vendor or third-party compromise", "principle": "CC", "series": "CC9", "likelihood": "medium", "impact": "high"},
        {"risk": "Inadequate incident response", "principle": "CC", "series": "CC7", "likelihood": "low", "impact": "high"},
    ]

    ai_risks = [
        {"risk": "AI model drift degrading processing accuracy", "principle": "PI", "series": "PI1", "likelihood": "high", "impact": "high"},
        {"risk": "Adversarial attacks on AI models", "principle": "CC", "series": "CC7", "likelihood": "medium", "impact": "high"},
        {"risk": "Training data bias causing unfair outcomes", "principle": "PI", "series": "PI1", "likelihood": "high", "impact": "high"},
        {"risk": "AI model extraction or intellectual property theft", "principle": "C", "series": "C1", "likelihood": "medium", "impact": "high"},
        {"risk": "Training data memorization leaking personal information", "principle": "P", "series": "P1", "likelihood": "medium", "impact": "high"},
        {"risk": "GPU/compute resource exhaustion affecting availability", "principle": "A", "series": "A1", "likelihood": "medium", "impact": "medium"},
        {"risk": "Prompt injection compromising system integrity", "principle": "CC", "series": "CC6", "likelihood": "high", "impact": "high"},
    ]

    risks_to_assess = standard_risks + (ai_risks if ai_specific else [])
    if known_risks:
        for kr in known_risks:
            risks_to_assess.append({"risk": kr, "principle": "CC", "series": "CC3", "likelihood": "medium", "impact": "medium"})

    score_map = {"high": 3, "medium": 2, "low": 1}
    risk_register = []

    for risk in risks_to_assess:
        l_score = score_map[risk["likelihood"]]
        i_score = score_map[risk["impact"]]
        total = l_score * i_score
        level = "critical" if total >= 8 else "high" if total >= 6 else "medium" if total >= 4 else "low"

        risk_register.append({
            "risk_description": risk["risk"],
            "trust_principle": risk["principle"],
            "relevant_series": risk["series"],
            "likelihood": risk["likelihood"],
            "impact": risk["impact"],
            "risk_score": total,
            "risk_level": level,
            "response": "mitigate" if level in ("critical", "high") else "monitor",
        })

    risk_register.sort(key=lambda r: r["risk_score"], reverse=True)

    result = {
        "assessment_type": "SOC 2 Risk Assessment (AICPA)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system_description,
        "service_commitments": service_commitments,
        "risk_register": risk_register,
        "risk_distribution": {
            "critical": len([r for r in risk_register if r["risk_level"] == "critical"]),
            "high": len([r for r in risk_register if r["risk_level"] == "high"]),
            "medium": len([r for r in risk_register if r["risk_level"] == "medium"]),
            "low": len([r for r in risk_register if r["risk_level"] == "low"]),
        },
        "overall_risk_posture": (
            "HIGH — significant risks require immediate attention"
            if any(r["risk_level"] == "critical" for r in risk_register)
            else "MODERATE — risks manageable with proper controls"
        ),
    }

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# TOOL 5: Crosswalk to ISO 27001
# ---------------------------------------------------------------------------
@mcp.tool()
def crosswalk_to_iso27001(
    soc2_series: Optional[list[str]] = None,
    focus_principle: str = "all",
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Map SOC 2 controls to ISO 27001 Annex A controls. Shows how SOC 2
    compliance overlaps with ISO 27001 certification requirements, enabling
    organizations pursuing dual compliance to identify shared controls.

    Args:
        soc2_series: Specific SOC 2 series to map (e.g. ["CC6", "CC7", "A1"])
        focus_principle: Filter by principle: "all", "CC", "A", "PI", "C", or "P"
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    if soc2_series:
        target_keys = soc2_series
    elif focus_principle != "all":
        target_keys = [k for k in SOC2_ISO27001_CROSSWALK if k.startswith(focus_principle[0])]
    else:
        target_keys = list(SOC2_ISO27001_CROSSWALK.keys())

    mappings = []
    total_iso_controls = set()

    for key in target_keys:
        if key not in SOC2_ISO27001_CROSSWALK:
            continue
        xw = SOC2_ISO27001_CROSSWALK[key]
        total_iso_controls.update(xw["iso27001"])
        mappings.append({
            "soc2_series": key,
            "iso27001_controls": xw["iso27001"],
            "mapping_note": xw["note"],
        })

    result = {
        "crosswalk_type": "SOC 2 to ISO/IEC 27001:2022 Control Mapping",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mappings": mappings,
        "summary": {
            "soc2_series_mapped": len(mappings),
            "unique_iso27001_controls": len(total_iso_controls),
            "iso27001_coverage_note": f"{len(total_iso_controls)} of 93 ISO 27001 Annex A controls are directly addressed by SOC 2 criteria.",
            "recommendation": (
                "SOC 2 provides strong coverage of ISO 27001 organizational and technological controls. "
                "Gaps exist primarily in physical controls (A.7) and some operational specifics. "
                "Organizations pursuing both should build a unified control framework."
            ),
        },
    }

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# TOOL 6: Readiness Checklist
# ---------------------------------------------------------------------------
@mcp.tool()
def readiness_checklist(
    audit_type: str = "type2",
    organization_maturity: str = "moderate",
    ai_system: bool = True,
    current_certifications: Optional[list[str]] = None,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """SOC 2 Type I/II readiness assessment. Generates a comprehensive
    pre-audit checklist with timeline, resource requirements, and
    AI-specific considerations.

    Args:
        audit_type: "type1" (point-in-time design) or "type2" (operating effectiveness over time)
        organization_maturity: "low", "moderate", or "high" — current security maturity
        ai_system: Whether the service includes AI/ML components
        current_certifications: Existing certifications that provide head start (e.g. ["ISO27001", "GDPR"])
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    certs = set(current_certifications or [])
    has_iso = any("27001" in c for c in certs)
    has_gdpr = any("gdpr" in c.lower() for c in certs)

    timeline_weeks = {"type1": {"low": 16, "moderate": 10, "high": 6}, "type2": {"low": 52, "moderate": 36, "high": 24}}
    weeks = timeline_weeks.get(audit_type, timeline_weeks["type2"]).get(organization_maturity, 36)
    if has_iso:
        weeks = int(weeks * 0.7)

    checklist = {
        "assessment_type": f"SOC 2 {audit_type.upper()} Readiness Assessment",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "organization_maturity": organization_maturity,
        "existing_certifications": list(certs),
        "readiness_checklist": {
            "phase_1_scoping": {
                "timeline": "Weeks 1-2",
                "items": [
                    {"item": "Define system boundaries and scope", "status": "TODO", "priority": "critical"},
                    {"item": "Select Trust Service Criteria in scope", "status": "TODO", "priority": "critical"},
                    {"item": "Draft System Description", "status": "TODO", "priority": "critical"},
                    {"item": "Identify principal service commitments and system requirements", "status": "TODO", "priority": "critical"},
                    {"item": "Select and engage CPA firm / auditor", "status": "TODO", "priority": "high"},
                ],
            },
            "phase_2_gap_assessment": {
                "timeline": f"Weeks 3-{min(6, weeks//4)}",
                "items": [
                    {"item": "Perform internal gap assessment against selected criteria", "status": "TODO", "priority": "critical"},
                    {"item": "Document all existing controls", "status": "TODO", "priority": "critical"},
                    {"item": "Identify control gaps and remediation plan", "status": "TODO", "priority": "critical"},
                    {"item": "Perform risk assessment (CC3)", "status": "TODO", "priority": "high"},
                    {"item": "Review vendor and third-party controls (CC9)", "status": "TODO", "priority": "high"},
                ],
            },
            "phase_3_remediation": {
                "timeline": f"Weeks {min(7, weeks//4)+1}-{weeks//2}",
                "items": [
                    {"item": "Implement missing controls from gap assessment", "status": "TODO", "priority": "critical"},
                    {"item": "Document all policies and procedures", "status": "TODO", "priority": "critical"},
                    {"item": "Implement monitoring and logging controls (CC4, CC7)", "status": "TODO", "priority": "high"},
                    {"item": "Establish incident response procedures (CC7.4)", "status": "TODO", "priority": "high"},
                    {"item": "Implement access control reviews (CC6)", "status": "TODO", "priority": "high"},
                    {"item": "Set up change management process (CC8)", "status": "TODO", "priority": "high"},
                ],
            },
            "phase_4_evidence_collection": {
                "timeline": f"Weeks {weeks//2+1}-{weeks-4}" if audit_type == "type2" else "N/A for Type I",
                "items": (
                    [
                        {"item": "Operate controls for observation period (min 6 months)", "status": "TODO", "priority": "critical"},
                        {"item": "Collect evidence of control operation", "status": "TODO", "priority": "critical"},
                        {"item": "Maintain audit logs and access reviews", "status": "TODO", "priority": "high"},
                        {"item": "Document all security incidents and responses", "status": "TODO", "priority": "high"},
                        {"item": "Conduct quarterly access reviews", "status": "TODO", "priority": "high"},
                        {"item": "Perform vulnerability scans and penetration tests", "status": "TODO", "priority": "high"},
                    ]
                    if audit_type == "type2"
                    else [{"item": "Type I does not require observation period", "status": "N/A", "priority": "info"}]
                ),
            },
            "phase_5_audit": {
                "timeline": f"Weeks {weeks-3}-{weeks}",
                "items": [
                    {"item": "Auditor fieldwork and evidence review", "status": "TODO", "priority": "critical"},
                    {"item": "Management representation letter", "status": "TODO", "priority": "critical"},
                    {"item": "Address any auditor findings", "status": "TODO", "priority": "high"},
                    {"item": "Report issuance", "status": "TODO", "priority": "high"},
                ],
            },
        },
        "estimated_timeline_weeks": weeks,
        "estimated_cost_range_usd": {
            "audit_fees": "$20,000 - $100,000" if audit_type == "type2" else "$15,000 - $50,000",
            "remediation": "$10,000 - $50,000" if organization_maturity != "high" else "$5,000 - $15,000",
            "tooling": "$5,000 - $30,000/year (GRC platform, monitoring tools)",
        },
    }

    if ai_system:
        checklist["ai_specific_requirements"] = {
            "additional_items": [
                {"item": "Document AI model inventory and lifecycle", "priority": "critical"},
                {"item": "Implement AI model monitoring for drift and bias", "priority": "critical"},
                {"item": "Establish AI-specific incident response procedures", "priority": "high"},
                {"item": "Document training data provenance and quality controls", "priority": "high"},
                {"item": "Implement AI access controls (model access, training data access)", "priority": "high"},
                {"item": "Establish AI change management (model versioning, deployment gates)", "priority": "high"},
                {"item": "Implement prompt injection protections", "priority": "high"},
                {"item": "Document AI processing integrity controls (validation, accuracy monitoring)", "priority": "high"},
            ],
            "note": "AI systems introduce additional risk factors across all Trust Service Criteria. Auditors are increasingly focusing on AI-specific controls.",
        }

    if has_iso:
        checklist["iso27001_head_start"] = {
            "note": "ISO 27001 certification provides significant overlap with SOC 2 Common Criteria (Security).",
            "estimated_controls_covered": "~60% of CC criteria already addressed by ISO 27001 ISMS",
            "key_gaps": ["SOC 2 Availability criteria", "SOC 2 Processing Integrity criteria", "SOC 2 Privacy criteria (use ISO 27701)"],
        }

    return json.dumps(checklist, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
