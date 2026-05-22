from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nvd_mcp_server.models.validators import VectorStringType, validate_vector_string


class AttackVector(str, Enum):
    """Attack Vector enumeration for CVSS 3.1."""

    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class ModifiedAttackVector(str, Enum):
    """Modified Attack Vector enumeration for CVSS 3.1."""

    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"
    NOT_DEFINED = "NOT_DEFINED"


class AttackComplexity(str, Enum):
    """Attack Complexity enumeration for CVSS 3.1."""

    HIGH = "HIGH"
    LOW = "LOW"


class ModifiedAttackComplexity(str, Enum):
    """Modified Attack Complexity enumeration for CVSS 3.1."""

    HIGH = "HIGH"
    LOW = "LOW"
    NOT_DEFINED = "NOT_DEFINED"


class PrivilegesRequired(str, Enum):
    """Privileges Required enumeration for CVSS 3.1."""

    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"


class ModifiedPrivilegesRequired(str, Enum):
    """Modified Privileges Required enumeration for CVSS 3.1."""

    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"
    NOT_DEFINED = "NOT_DEFINED"


class UserInteraction(str, Enum):
    """User Interaction enumeration for CVSS 3.1."""

    NONE = "NONE"
    REQUIRED = "REQUIRED"


class ModifiedUserInteraction(str, Enum):
    """Modified User Interaction enumeration for CVSS 3.1."""

    NONE = "NONE"
    REQUIRED = "REQUIRED"
    NOT_DEFINED = "NOT_DEFINED"


class Scope(str, Enum):
    """Scope enumeration for CVSS 3.1."""

    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"


class ModifiedScope(str, Enum):
    """Modified Scope enumeration for CVSS 3.1."""

    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    NOT_DEFINED = "NOT_DEFINED"


class CiaImpact(str, Enum):
    """Confidentiality, Integrity, Availability Impact enumeration for CVSS 3.1."""

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class ModifiedCiaImpact(str, Enum):
    """
    Modified Confidentiality, Integrity, Availability Impact enumeration for CVSS 3.1.
    """

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ExploitCodeMaturity(str, Enum):
    """Exploit Code Maturity enumeration for CVSS 3.1."""

    UNPROVEN = "UNPROVEN"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    FUNCTIONAL = "FUNCTIONAL"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class RemediationLevel(str, Enum):
    """Remediation Level enumeration for CVSS 3.1."""

    OFFICIAL_FIX = "OFFICIAL_FIX"
    TEMPORARY_FIX = "TEMPORARY_FIX"
    WORKAROUND = "WORKAROUND"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_DEFINED = "NOT_DEFINED"


class ReportConfidence(str, Enum):
    """Report Confidence enumeration for CVSS 3.1."""

    UNKNOWN = "UNKNOWN"
    REASONABLE = "REASONABLE"
    CONFIRMED = "CONFIRMED"
    NOT_DEFINED = "NOT_DEFINED"


class CiaRequirement(str, Enum):
    """Confidentiality, Integrity, Availability Requirement enumeration for CVSS 3.1."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class Severity(str, Enum):
    """Severity enumeration for CVSS 3.1."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CvssVersion(str, Enum):
    """CVSS Version enumeration."""

    V3_1 = "3.1"


class CvssV31Model(BaseModel):
    """
    Pydantic model for Common Vulnerability Scoring System (CVSS) version 3.1.

    This model represents a complete CVSS v3.1 vulnerability assessment including
    base metrics, temporal metrics, and environmental metrics. The base score and
    severity are required, while temporal and environmental metrics are optional.
    """

    version: CvssVersion = Field(..., description="CVSS Version - must be 3.1")

    vector_string: str = Field(
        ...,
        alias="vectorString",
        description="CVSS vector string representation of the vulnerability metrics",
    )

    # Base Metrics (Required)
    attack_vector: AttackVector = Field(
        ...,
        alias="attackVector",
        description=(
            "Attack Vector - describes the context by which vulnerability "
            "exploitation is possible"
        ),
    )

    attack_complexity: AttackComplexity = Field(
        ...,
        alias="attackComplexity",
        description=(
            "Attack Complexity - describes the conditions beyond the attacker's control"
        ),
    )

    privileges_required: PrivilegesRequired = Field(
        ...,
        alias="privilegesRequired",
        description=(
            "Privileges Required - describes the level of privileges an "
            "attacker must possess"
        ),
    )

    user_interaction: UserInteraction = Field(
        ...,
        alias="userInteraction",
        description=(
            "User Interaction - captures the requirement for a human user "
            "to participate in the attack"
        ),
    )

    scope: Scope = Field(
        ...,
        description=(
            "Scope - determines if a vulnerability can affect resources "
            "beyond its security scope"
        ),
    )

    confidentiality_impact: CiaImpact = Field(
        ...,
        alias="confidentialityImpact",
        description=(
            "Confidentiality Impact - measures the impact to confidentiality "
            "of information"
        ),
    )

    integrity_impact: CiaImpact = Field(
        ...,
        alias="integrityImpact",
        description=(
            "Integrity Impact - measures the impact to integrity of information"
        ),
    )

    availability_impact: CiaImpact = Field(
        ...,
        alias="availabilityImpact",
        description=(
            "Availability Impact - measures the impact to availability of information"
        ),
    )

    base_score: float = Field(
        ...,
        alias="baseScore",
        ge=0.0,
        le=10.0,
        description=(
            "Base Score - represents the intrinsic characteristics of a vulnerability"
        ),
    )

    base_severity: Severity = Field(
        ...,
        alias="baseSeverity",
        description="Base Severity - qualitative rating of the base score",
    )

    # Temporal Metrics (Optional)
    exploit_code_maturity: Optional[ExploitCodeMaturity] = Field(
        None,
        alias="exploitCodeMaturity",
        description=(
            "Exploit Code Maturity - measures the likelihood of the "
            "vulnerability being attacked"
        ),
    )

    remediation_level: Optional[RemediationLevel] = Field(
        None,
        alias="remediationLevel",
        description=(
            "Remediation Level - measures the availability of a fix for "
            "the vulnerability"
        ),
    )

    report_confidence: Optional[ReportConfidence] = Field(
        None,
        alias="reportConfidence",
        description=(
            "Report Confidence - measures the degree of confidence in the "
            "existence of the vulnerability"
        ),
    )

    temporal_score: Optional[float] = Field(
        None,
        alias="temporalScore",
        ge=0.0,
        le=10.0,
        description="Temporal Score - adjusts the base score based on temporal factors",
    )

    temporal_severity: Optional[Severity] = Field(
        None,
        alias="temporalSeverity",
        description="Temporal Severity - qualitative rating of the temporal score",
    )

    # Environmental Metrics (Optional)
    confidentiality_requirement: Optional[CiaRequirement] = Field(
        None,
        alias="confidentialityRequirement",
        description=(
            "Confidentiality Requirement - measures the importance of "
            "confidentiality in the environment"
        ),
    )

    integrity_requirement: Optional[CiaRequirement] = Field(
        None,
        alias="integrityRequirement",
        description=(
            "Integrity Requirement - measures the importance of integrity "
            "in the environment"
        ),
    )

    availability_requirement: Optional[CiaRequirement] = Field(
        None,
        alias="availabilityRequirement",
        description=(
            "Availability Requirement - measures the importance of "
            "availability in the environment"
        ),
    )

    modified_attack_vector: Optional[ModifiedAttackVector] = Field(
        None,
        alias="modifiedAttackVector",
        description=(
            "Modified Attack Vector - allows users to override the Attack Vector metric"
        ),
    )

    modified_attack_complexity: Optional[ModifiedAttackComplexity] = Field(
        None,
        alias="modifiedAttackComplexity",
        description=(
            "Modified Attack Complexity - allows users to override the "
            "Attack Complexity metric"
        ),
    )

    modified_privileges_required: Optional[ModifiedPrivilegesRequired] = Field(
        None,
        alias="modifiedPrivilegesRequired",
        description=(
            "Modified Privileges Required - allows users to override the "
            "Privileges Required metric"
        ),
    )

    modified_user_interaction: Optional[ModifiedUserInteraction] = Field(
        None,
        alias="modifiedUserInteraction",
        description=(
            "Modified User Interaction - allows users to override the "
            "User Interaction metric"
        ),
    )

    modified_scope: Optional[ModifiedScope] = Field(
        None,
        alias="modifiedScope",
        description="Modified Scope - allows users to override the Scope metric",
    )

    modified_confidentiality_impact: Optional[ModifiedCiaImpact] = Field(
        None,
        alias="modifiedConfidentialityImpact",
        description=(
            "Modified Confidentiality Impact - allows users to override the "
            "Confidentiality Impact metric"
        ),
    )

    modified_integrity_impact: Optional[ModifiedCiaImpact] = Field(
        None,
        alias="modifiedIntegrityImpact",
        description=(
            "Modified Integrity Impact - allows users to override the "
            "Integrity Impact metric"
        ),
    )

    modified_availability_impact: Optional[ModifiedCiaImpact] = Field(
        None,
        alias="modifiedAvailabilityImpact",
        description=(
            "Modified Availability Impact - allows users to override the "
            "Availability Impact metric"
        ),
    )

    environmental_score: Optional[float] = Field(
        None,
        alias="environmentalScore",
        ge=0.0,
        le=10.0,
        description=(
            "Environmental Score - adjusts the temporal score "
            "based on environmental factors"
        ),
    )

    environmental_severity: Optional[Severity] = Field(
        None,
        alias="environmentalSeverity",
        description=(
            "Environmental Severity - qualitative rating of the environmental score"
        ),
    )

    @field_validator("vector_string")
    @classmethod
    def validate_vector_string(cls, v: str) -> str:
        """
        Validate the CVSS vector string format according to CVSS 3.1 specification.

        Args:
            v: The vector string to validate

        Returns:
            The validated vector string

        Raises:
            ValueError: If the vector string format is invalid
        """
        return validate_vector_string(v, VectorStringType.V31)

    model_config = ConfigDict(
        validate_by_name=True,
        validate_by_alias=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )
