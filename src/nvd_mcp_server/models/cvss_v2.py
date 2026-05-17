"""
Pydantic v2 models for Common Vulnerability Scoring System (CVSS) version 2.0.

This module provides data validation and parsing for CVSS v2.0 vulnerability
scoring data
based on the JSON schema specification from FIRST.ORG.

Copyright (c) 2017, FIRST.ORG, INC.
Licensed under BSD 3-Clause License.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nvd_mcp_server.models.validators import VectorStringType, validate_vector_string


class AccessVectorType(str, Enum):
    """Access vector represents how the vulnerability is exploited."""

    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"


class AccessComplexityType(str, Enum):
    """
    Access complexity measures the complexity of the attack required to exploit
    the vulnerability.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AuthenticationType(str, Enum):
    """
    Authentication measures the number of times an attacker must authenticate to
    a target.
    """

    MULTIPLE = "MULTIPLE"
    SINGLE = "SINGLE"
    NONE = "NONE"


class CiaType(str, Enum):
    """CIA (Confidentiality, Integrity, Availability) impact types."""

    NONE = "NONE"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"


class ExploitabilityType(str, Enum):
    """
    Exploitability measures the current state of exploit techniques or code
    availability.
    """

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


class ReportConfidenceType(str, Enum):
    """
    Report confidence measures the degree of confidence in the existence of the
    vulnerability.
    """

    UNCONFIRMED = "UNCONFIRMED"
    UNCORROBORATED = "UNCORROBORATED"
    CONFIRMED = "CONFIRMED"
    NOT_DEFINED = "NOT_DEFINED"


class CollateralDamagePotentialType(str, Enum):
    """
    Collateral damage potential measures the potential for loss of life or
    physical assets.
    """

    NONE = "NONE"
    LOW = "LOW"
    LOW_MEDIUM = "LOW_MEDIUM"
    MEDIUM_HIGH = "MEDIUM_HIGH"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class TargetDistributionType(str, Enum):
    """Target distribution measures the proportion of vulnerable systems."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class CiaRequirementType(str, Enum):
    """CIA requirement types for environmental scoring."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class CvssV2Model(BaseModel):
    """
    CVSS v2.0 vulnerability scoring model.

    This model represents a complete CVSS v2.0 score with base, temporal, and
    environmental metrics.
    All scores range from 0.0 to 10.0, with higher scores indicating more severe
    vulnerabilities.
    """

    version: str = Field(
        ..., description="CVSS Version - must be '2.0'", pattern=r"^2\.0$"
    )

    vector_string: str = Field(
        ...,
        alias="vectorString",
        description="Compressed textual representation of the CVSS metrics",
    )

    # Base Score Metrics (Required)
    access_vector: AccessVectorType = Field(
        ..., alias="accessVector", description="How the vulnerability is exploited"
    )

    access_complexity: AccessComplexityType = Field(
        ...,
        alias="accessComplexity",
        description="Complexity of the attack required to exploit the vulnerability",
    )

    authentication: AuthenticationType = Field(
        ...,
        alias="authentication",
        description=(
            "Number of times an attacker must authenticate to exploit the vulnerability"
        ),
    )

    confidentiality_impact: CiaType = Field(
        ...,
        alias="confidentialityImpact",
        description="Impact on confidentiality of information resources",
    )

    integrity_impact: CiaType = Field(
        ..., alias="integrityImpact", description="Impact on integrity of the system"
    )

    availability_impact: CiaType = Field(
        ...,
        alias="availabilityImpact",
        description="Impact on availability of the impacted component",
    )

    base_score: float = Field(
        ...,
        alias="baseScore",
        description="Base score calculated from base metrics",
        ge=0.0,
        le=10.0,
    )

    # Temporal Score Metrics (Optional)
    exploitability: Optional[ExploitabilityType] = Field(
        None, description="Current state of exploit techniques or code availability"
    )

    remediation_level: Optional[RemediationLevelType] = Field(
        None,
        alias="remediationLevel",
        description="Level of remediation available for the vulnerability",
    )

    report_confidence: Optional[ReportConfidenceType] = Field(
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

    # Environmental Score Metrics (Optional)
    collateral_damage_potential: Optional[CollateralDamagePotentialType] = Field(
        None,
        alias="collateralDamagePotential",
        description="Potential for loss of life or physical assets",
    )

    target_distribution: Optional[TargetDistributionType] = Field(
        None, alias="targetDistribution", description="Proportion of vulnerable systems"
    )

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

    environmental_score: Optional[float] = Field(
        None,
        alias="environmentalScore",
        description="Environmental score customized for specific environment",
        ge=0.0,
        le=10.0,
    )

    @field_validator("vector_string")
    @classmethod
    def validate_vector_string(cls, v: str) -> str:
        """Validate the CVSS vector string format."""
        return validate_vector_string(v, VectorStringType.V2)

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate that version is exactly '2.0'."""
        if v != "2.0":
            raise ValueError(f"Invalid CVSS version: {v}. Must be '2.0'")
        return v

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)


# Convenience function to create minimal CVSS v2.0 score
def create_base_cvss_v2(
    vector_string: str,
    access_vector: AccessVectorType,
    access_complexity: AccessComplexityType,
    authentication: AuthenticationType,
    confidentiality_impact: CiaType,
    integrity_impact: CiaType,
    availability_impact: CiaType,
    base_score: float,
) -> CvssV2Model:
    """
    Create a minimal CVSS v2.0 model with only base score metrics.

    Args:
        vector_string: Compressed textual representation of the CVSS metrics
        access_vector: How the vulnerability is exploited
        access_complexity: Complexity of the attack required
        authentication: Number of times an attacker must authenticate
        confidentiality_impact: Impact on confidentiality
        integrity_impact: Impact on integrity
        availability_impact: Impact on availability
        base_score: Base score (0.0 to 10.0)

    Returns:
        CvssV2Model: A validated CVSS v2.0 model instance
    """
    return CvssV2Model(
        version="2.0",
        vector_string=vector_string,
        access_vector=access_vector,
        access_complexity=access_complexity,
        authentication=authentication,
        confidentiality_impact=confidentiality_impact,
        integrity_impact=integrity_impact,
        availability_impact=availability_impact,
        base_score=base_score,
    )
