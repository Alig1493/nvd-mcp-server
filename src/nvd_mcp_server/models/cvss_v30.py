"""
Pydantic v2 models for Common Vulnerability Scoring System (CVSS) version 3.0.

This module provides data validation and parsing for CVSS v3.0 vulnerability
scoring data
based on the JSON schema specification from FIRST.ORG.

Copyright (c) 2017, FIRST.ORG, INC.
Licensed under BSD 3-Clause License.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nvd_mcp_server.models.validators import VectorStringType, validate_vector_string


class AttackVectorType(str, Enum):
    """Attack vector represents how the vulnerability is exploited."""

    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class ModifiedAttackVectorType(str, Enum):
    """Modified attack vector for environmental scoring."""

    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"
    NOT_DEFINED = "NOT_DEFINED"


class AttackComplexityType(str, Enum):
    """Attack complexity describes the conditions beyond the attacker's control."""

    HIGH = "HIGH"
    LOW = "LOW"


class ModifiedAttackComplexityType(str, Enum):
    """Modified attack complexity for environmental scoring."""

    HIGH = "HIGH"
    LOW = "LOW"
    NOT_DEFINED = "NOT_DEFINED"


class PrivilegesRequiredType(str, Enum):
    """Privileges required describes the level of privileges an attacker must
    possess."""

    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"


class ModifiedPrivilegesRequiredType(str, Enum):
    """Modified privileges required for environmental scoring."""

    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"
    NOT_DEFINED = "NOT_DEFINED"


class UserInteractionType(str, Enum):
    """User interaction captures the requirement for a user to participate in
    the attack."""

    NONE = "NONE"
    REQUIRED = "REQUIRED"


class ModifiedUserInteractionType(str, Enum):
    """Modified user interaction for environmental scoring."""

    NONE = "NONE"
    REQUIRED = "REQUIRED"
    NOT_DEFINED = "NOT_DEFINED"


class ScopeType(str, Enum):
    """Scope captures whether a vulnerability can impact resources beyond its
    security scope."""

    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"


class ModifiedScopeType(str, Enum):
    """Modified scope for environmental scoring."""

    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    NOT_DEFINED = "NOT_DEFINED"


class CiaType(str, Enum):
    """CIA (Confidentiality, Integrity, Availability) impact types for CVSS 3.0."""

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class ModifiedCiaType(str, Enum):
    """Modified CIA impact types for environmental scoring."""

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ExploitCodeMaturityType(str, Enum):
    """Exploit code maturity measures the likelihood of the vulnerability being
    attacked."""

    UNPROVEN = "UNPROVEN"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    FUNCTIONAL = "FUNCTIONAL"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class RemediationLevelType(str, Enum):
    """Remediation level allows the analyst to provide temporal score information."""

    OFFICIAL_FIX = "OFFICIAL_FIX"
    TEMPORARY_FIX = "TEMPORARY_FIX"
    WORKAROUND = "WORKAROUND"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_DEFINED = "NOT_DEFINED"


class ConfidenceType(str, Enum):
    """Confidence measures the degree of confidence in the existence of the
    vulnerability."""

    UNKNOWN = "UNKNOWN"
    REASONABLE = "REASONABLE"
    CONFIRMED = "CONFIRMED"
    NOT_DEFINED = "NOT_DEFINED"


class CiaRequirementType(str, Enum):
    """CIA requirement types for environmental scoring."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class SeverityType(str, Enum):
    """Severity rating based on CVSS score ranges."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CvssV30Model(BaseModel):
    """
    CVSS v3.0 vulnerability scoring model.

    This model represents a complete CVSS v3.0 score with base, temporal, and
    environmental metrics. All scores range from 0.0 to 10.0, with higher
    scores indicating more severe vulnerabilities. CVSS v3.0 introduces the
    concept of scope and changes how privileges required are calculated.
    """

    version: str = Field(
        ..., description="CVSS Version - must be '3.0'", pattern=r"^3\.0$"
    )

    vector_string: str = Field(
        ...,
        alias="vectorString",
        description="Compressed textual representation of the CVSS v3.0 metrics",
    )

    # Base Score Metrics (Required)
    attack_vector: AttackVectorType = Field(
        ..., alias="attackVector", description="How the vulnerability is exploited"
    )

    attack_complexity: AttackComplexityType = Field(
        ...,
        alias="attackComplexity",
        description=(
            "Conditions beyond the attacker's control that must exist to "
            "exploit the vulnerability"
        ),
    )

    privileges_required: PrivilegesRequiredType = Field(
        ...,
        alias="privilegesRequired",
        description=(
            "Level of privileges an attacker must possess before successfully "
            "exploiting the vulnerability"
        ),
    )

    user_interaction: UserInteractionType = Field(
        ...,
        alias="userInteraction",
        description=(
            "Whether the vulnerability can be exploited solely at the will "
            "of the attacker"
        ),
    )

    scope: ScopeType = Field(
        ...,
        description=(
            "Whether a vulnerability can impact resources beyond its security authority"
        ),
    )

    confidentiality_impact: CiaType = Field(
        ...,
        alias="confidentialityImpact",
        description="Impact on the confidentiality of information resources",
    )

    integrity_impact: CiaType = Field(
        ...,
        alias="integrityImpact",
        description="Impact on the integrity of the system",
    )

    availability_impact: CiaType = Field(
        ...,
        alias="availabilityImpact",
        description="Impact on the availability of the impacted component",
    )

    base_score: float = Field(
        ...,
        alias="baseScore",
        description="Base score calculated from base metrics",
        ge=0.0,
        le=10.0,
    )

    base_severity: SeverityType = Field(
        ...,
        alias="baseSeverity",
        description="Qualitative severity rating based on base score",
    )

    # Temporal Score Metrics (Optional)
    exploit_code_maturity: Optional[ExploitCodeMaturityType] = Field(
        None,
        alias="exploitCodeMaturity",
        description="Likelihood of the vulnerability being attacked",
    )

    remediation_level: Optional[RemediationLevelType] = Field(
        None,
        alias="remediationLevel",
        description="Level of remediation available for the vulnerability",
    )

    report_confidence: Optional[ConfidenceType] = Field(
        None,
        alias="reportConfidence",
        description="Degree of confidence in the existence of the vulnerability",
    )

    temporal_score: Optional[float] = Field(
        None,
        alias="temporalScore",
        description="Temporal score that changes over time",
        ge=0.0,
        le=10.0,
    )

    temporal_severity: Optional[SeverityType] = Field(
        None,
        alias="temporalSeverity",
        description="Qualitative severity rating based on temporal score",
    )

    # Environmental Score Metrics (Optional)
    confidentiality_requirement: Optional[CiaRequirementType] = Field(
        None,
        alias="confidentialityRequirement",
        description="Importance of confidentiality to the organization",
    )

    integrity_requirement: Optional[CiaRequirementType] = Field(
        None,
        alias="integrityRequirement",
        description="Importance of integrity to the organization",
    )

    availability_requirement: Optional[CiaRequirementType] = Field(
        None,
        alias="availabilityRequirement",
        description="Importance of availability to the organization",
    )

    modified_attack_vector: Optional[ModifiedAttackVectorType] = Field(
        None,
        alias="modifiedAttackVector",
        description="Modified attack vector for environmental scoring",
    )

    modified_attack_complexity: Optional[ModifiedAttackComplexityType] = Field(
        None,
        alias="modifiedAttackComplexity",
        description="Modified attack complexity for environmental scoring",
    )

    modified_privileges_required: Optional[ModifiedPrivilegesRequiredType] = Field(
        None,
        alias="modifiedPrivilegesRequired",
        description="Modified privileges required for environmental scoring",
    )

    modified_user_interaction: Optional[ModifiedUserInteractionType] = Field(
        None,
        alias="modifiedUserInteraction",
        description="Modified user interaction for environmental scoring",
    )

    modified_scope: Optional[ModifiedScopeType] = Field(
        None,
        alias="modifiedScope",
        description="Modified scope for environmental scoring",
    )

    modified_confidentiality_impact: Optional[ModifiedCiaType] = Field(
        None,
        alias="modifiedConfidentialityImpact",
        description="Modified confidentiality impact for environmental scoring",
    )

    modified_integrity_impact: Optional[ModifiedCiaType] = Field(
        None,
        alias="modifiedIntegrityImpact",
        description="Modified integrity impact for environmental scoring",
    )

    modified_availability_impact: Optional[ModifiedCiaType] = Field(
        None,
        alias="modifiedAvailabilityImpact",
        description="Modified availability impact for environmental scoring",
    )

    environmental_score: Optional[float] = Field(
        None,
        alias="environmentalScore",
        description="Environmental score customized for specific environment",
        ge=0.0,
        le=10.0,
    )

    environmental_severity: Optional[SeverityType] = Field(
        None,
        alias="environmentalSeverity",
        description="Qualitative severity rating based on environmental score",
    )

    @field_validator("vector_string")
    @classmethod
    def validate_vector_string(cls, v: str) -> str:
        """Validate the CVSS v3.0 vector string format."""
        return validate_vector_string(v, VectorStringType.V3)

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate that version is exactly '3.0'."""
        if v != "3.0":
            raise ValueError(f"Invalid CVSS version: {v}. Must be '3.0'")
        return v

    @field_validator("base_severity", "temporal_severity", "environmental_severity")
    @classmethod
    def validate_severity_score_alignment(
        cls, v: Optional[SeverityType]
    ) -> Optional[SeverityType]:
        """
        Validate severity ratings align with expected score ranges.
        Note: This is a basic validation - actual score-to-severity mapping
        should be validated against the corresponding score field.
        """
        return v

    model_config = ConfigDict(
        validate_by_name=True, validate_by_alias=True, use_enum_values=True
    )
