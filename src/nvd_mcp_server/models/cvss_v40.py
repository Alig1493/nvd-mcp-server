"""
Pydantic v2 models for Common Vulnerability Scoring System version 4.0

Based on the JSON Schema from FIRST.ORG, INC.
Schema ID: https://www.first.org/cvss/cvss-v4.0.json?20240216
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nvd_mcp_server.models.validators import VectorStringType, validate_vector_string


class AttackVectorType(str, Enum):
    """Attack Vector enumeration for CVSS 4.0"""

    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class ModifiedAttackVectorType(str, Enum):
    """Modified Attack Vector enumeration for CVSS 4.0"""

    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"
    NOT_DEFINED = "NOT_DEFINED"


class AttackComplexityType(str, Enum):
    """Attack Complexity enumeration for CVSS 4.0"""

    HIGH = "HIGH"
    LOW = "LOW"


class ModifiedAttackComplexityType(str, Enum):
    """Modified Attack Complexity enumeration for CVSS 4.0"""

    HIGH = "HIGH"
    LOW = "LOW"
    NOT_DEFINED = "NOT_DEFINED"


class AttackRequirementsType(str, Enum):
    """Attack Requirements enumeration for CVSS 4.0"""

    NONE = "NONE"
    PRESENT = "PRESENT"


class ModifiedAttackRequirementsType(str, Enum):
    """Modified Attack Requirements enumeration for CVSS 4.0"""

    NONE = "NONE"
    PRESENT = "PRESENT"
    NOT_DEFINED = "NOT_DEFINED"


class PrivilegesRequiredType(str, Enum):
    """Privileges Required enumeration for CVSS 4.0"""

    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"


class ModifiedPrivilegesRequiredType(str, Enum):
    """Modified Privileges Required enumeration for CVSS 4.0"""

    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"
    NOT_DEFINED = "NOT_DEFINED"


class UserInteractionType(str, Enum):
    """User Interaction enumeration for CVSS 4.0"""

    NONE = "NONE"
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"


class ModifiedUserInteractionType(str, Enum):
    """Modified User Interaction enumeration for CVSS 4.0"""

    NONE = "NONE"
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"
    NOT_DEFINED = "NOT_DEFINED"


class VulnCiaType(str, Enum):
    """
    Vulnerability CIA (Confidentiality, Integrity, Availability)
    enumeration for CVSS 4.0
    """

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class ModifiedVulnCiaType(str, Enum):
    """Modified Vulnerability CIA enumeration for CVSS 4.0"""

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class SubCiaType(str, Enum):
    """Subsequent CIA enumeration for CVSS 4.0"""

    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class ModifiedSubCType(str, Enum):
    """Modified Subsequent Confidentiality enumeration for CVSS 4.0"""

    NEGLIGIBLE = "NEGLIGIBLE"
    LOW = "LOW"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ModifiedSubIaType(str, Enum):
    """Modified Subsequent Integrity/Availability enumeration for CVSS 4.0"""

    NEGLIGIBLE = "NEGLIGIBLE"
    LOW = "LOW"
    HIGH = "HIGH"
    SAFETY = "SAFETY"
    NOT_DEFINED = "NOT_DEFINED"


class ExploitMaturityType(str, Enum):
    """Exploit Maturity enumeration for CVSS 4.0"""

    UNREPORTED = "UNREPORTED"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    ATTACKED = "ATTACKED"
    NOT_DEFINED = "NOT_DEFINED"


class CiaRequirementType(str, Enum):
    """CIA Requirement enumeration for CVSS 4.0"""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class SafetyType(str, Enum):
    """Safety enumeration for CVSS 4.0"""

    NEGLIGIBLE = "NEGLIGIBLE"
    PRESENT = "PRESENT"
    NOT_DEFINED = "NOT_DEFINED"


class AutomatableType(str, Enum):
    """Automatable enumeration for CVSS 4.0"""

    NO = "NO"
    YES = "YES"
    NOT_DEFINED = "NOT_DEFINED"


class RecoveryType(str, Enum):
    """Recovery enumeration for CVSS 4.0"""

    AUTOMATIC = "AUTOMATIC"
    USER = "USER"
    IRRECOVERABLE = "IRRECOVERABLE"
    NOT_DEFINED = "NOT_DEFINED"


class ValueDensityType(str, Enum):
    """Value Density enumeration for CVSS 4.0"""

    DIFFUSE = "DIFFUSE"
    CONCENTRATED = "CONCENTRATED"
    NOT_DEFINED = "NOT_DEFINED"


class VulnerabilityResponseEffortType(str, Enum):
    """Vulnerability Response Effort enumeration for CVSS 4.0"""

    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ProviderUrgencyType(str, Enum):
    """Provider Urgency enumeration for CVSS 4.0"""

    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"
    NOT_DEFINED = "NOT_DEFINED"


class SeverityType(str, Enum):
    """Severity enumeration for CVSS 4.0"""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CvssVersion(str, Enum):
    """CVSS Version enumeration"""

    V4_0 = "4.0"


class CvssV40Model(BaseModel):
    """
    Common Vulnerability Scoring System version 4.0 model

    This model represents a CVSS 4.0 vulnerability assessment with base metrics,
    threat metrics, and environmental metrics including their scores and severities.
    """

    # Required fields
    version: CvssVersion = Field(description="CVSS Version")

    vector_string: str = Field(
        alias="vectorString", description="CVSS vector string representation"
    )

    base_score: float = Field(
        alias="baseScore", ge=0.0, le=10.0, description="Base score from 0.0 to 10.0"
    )

    base_severity: SeverityType = Field(
        alias="baseSeverity", description="Base severity rating"
    )

    # Base metric group
    attack_vector: AttackVectorType = Field(
        alias="attackVector", description="Attack Vector metric"
    )

    attack_complexity: AttackComplexityType = Field(
        alias="attackComplexity", description="Attack Complexity metric"
    )

    attack_requirements: AttackRequirementsType = Field(
        alias="attackRequirements", description="Attack Requirements metric"
    )

    privileges_required: PrivilegesRequiredType = Field(
        alias="privilegesRequired", description="Privileges Required metric"
    )

    user_interaction: UserInteractionType = Field(
        alias="userInteraction", description="User Interaction metric"
    )

    vuln_confidentiality_impact: VulnCiaType = Field(
        alias="vulnConfidentialityImpact",
        description="Vulnerable system Confidentiality impact",
    )

    vuln_integrity_impact: VulnCiaType = Field(
        alias="vulnIntegrityImpact", description="Vulnerable system Integrity impact"
    )

    vuln_availability_impact: VulnCiaType = Field(
        alias="vulnAvailabilityImpact",
        description="Vulnerable system Availability impact",
    )

    sub_confidentiality_impact: SubCiaType = Field(
        alias="subConfidentialityImpact",
        description="Subsequent system Confidentiality impact",
    )

    sub_integrity_impact: SubCiaType = Field(
        alias="subIntegrityImpact", description="Subsequent system Integrity impact"
    )

    sub_availability_impact: SubCiaType = Field(
        alias="subAvailabilityImpact",
        description="Subsequent system Availability impact",
    )

    # Optional threat metric group
    threat_score: Optional[float] = Field(
        default=None,
        alias="threatScore",
        ge=0.0,
        le=10.0,
        description="Threat score from 0.0 to 10.0",
    )

    threat_severity: Optional[SeverityType] = Field(
        default=None, alias="threatSeverity", description="Threat severity rating"
    )

    exploit_maturity: ExploitMaturityType = Field(
        default=ExploitMaturityType.NOT_DEFINED,
        alias="exploitMaturity",
        description="Exploit Maturity metric",
    )

    # Optional environmental metric group
    environmental_score: Optional[float] = Field(
        default=None,
        alias="environmentalScore",
        ge=0.0,
        le=10.0,
        description="Environmental score from 0.0 to 10.0",
    )

    environmental_severity: Optional[SeverityType] = Field(
        default=None,
        alias="environmentalSeverity",
        description="Environmental severity rating",
    )

    confidentiality_requirement: CiaRequirementType = Field(
        default=CiaRequirementType.NOT_DEFINED,
        alias="confidentialityRequirement",
        description="Confidentiality Requirement metric",
    )

    integrity_requirement: CiaRequirementType = Field(
        default=CiaRequirementType.NOT_DEFINED,
        alias="integrityRequirement",
        description="Integrity Requirement metric",
    )

    availability_requirement: CiaRequirementType = Field(
        default=CiaRequirementType.NOT_DEFINED,
        alias="availabilityRequirement",
        description="Availability Requirement metric",
    )

    # Modified base metrics
    modified_attack_vector: ModifiedAttackVectorType = Field(
        default=ModifiedAttackVectorType.NOT_DEFINED,
        alias="modifiedAttackVector",
        description="Modified Attack Vector metric",
    )

    modified_attack_complexity: ModifiedAttackComplexityType = Field(
        default=ModifiedAttackComplexityType.NOT_DEFINED,
        alias="modifiedAttackComplexity",
        description="Modified Attack Complexity metric",
    )

    modified_attack_requirements: ModifiedAttackRequirementsType = Field(
        default=ModifiedAttackRequirementsType.NOT_DEFINED,
        alias="modifiedAttackRequirements",
        description="Modified Attack Requirements metric",
    )

    modified_privileges_required: ModifiedPrivilegesRequiredType = Field(
        default=ModifiedPrivilegesRequiredType.NOT_DEFINED,
        alias="modifiedPrivilegesRequired",
        description="Modified Privileges Required metric",
    )

    modified_user_interaction: ModifiedUserInteractionType = Field(
        default=ModifiedUserInteractionType.NOT_DEFINED,
        alias="modifiedUserInteraction",
        description="Modified User Interaction metric",
    )

    modified_vuln_confidentiality_impact: ModifiedVulnCiaType = Field(
        default=ModifiedVulnCiaType.NOT_DEFINED,
        alias="modifiedVulnConfidentialityImpact",
        description="Modified Vulnerable system Confidentiality impact",
    )

    modified_vuln_integrity_impact: ModifiedVulnCiaType = Field(
        default=ModifiedVulnCiaType.NOT_DEFINED,
        alias="modifiedVulnIntegrityImpact",
        description="Modified Vulnerable system Integrity impact",
    )

    modified_vuln_availability_impact: ModifiedVulnCiaType = Field(
        default=ModifiedVulnCiaType.NOT_DEFINED,
        alias="modifiedVulnAvailabilityImpact",
        description="Modified Vulnerable system Availability impact",
    )

    modified_sub_confidentiality_impact: ModifiedSubCType = Field(
        default=ModifiedSubCType.NOT_DEFINED,
        alias="modifiedSubConfidentialityImpact",
        description="Modified Subsequent system Confidentiality impact",
    )

    modified_sub_integrity_impact: ModifiedSubIaType = Field(
        default=ModifiedSubIaType.NOT_DEFINED,
        alias="modifiedSubIntegrityImpact",
        description="Modified Subsequent system Integrity impact",
    )

    modified_sub_availability_impact: ModifiedSubIaType = Field(
        default=ModifiedSubIaType.NOT_DEFINED,
        alias="modifiedSubAvailabilityImpact",
        description="Modified Subsequent system Availability impact",
    )

    # Supplemental metrics
    safety: SafetyType = Field(
        default=SafetyType.NOT_DEFINED, alias="Safety", description="Safety metric"
    )

    automatable: AutomatableType = Field(
        default=AutomatableType.NOT_DEFINED,
        alias="Automatable",
        description="Automatable metric",
    )

    recovery: RecoveryType = Field(
        default=RecoveryType.NOT_DEFINED,
        alias="Recovery",
        description="Recovery metric",
    )

    value_density: ValueDensityType = Field(
        default=ValueDensityType.NOT_DEFINED,
        alias="valueDensity",
        description="Value Density metric",
    )

    vulnerability_response_effort: VulnerabilityResponseEffortType = Field(
        default=VulnerabilityResponseEffortType.NOT_DEFINED,
        alias="vulnerabilityResponseEffort",
        description="Vulnerability Response Effort metric",
    )

    provider_urgency: ProviderUrgencyType = Field(
        default=ProviderUrgencyType.NOT_DEFINED,
        alias="providerUrgency",
        description="Provider Urgency metric",
    )

    @field_validator("vector_string")
    @classmethod
    def validate_vector_string(cls, v: str) -> str:
        """Validate CVSS 4.0 vector string format"""
        return validate_vector_string(v, VectorStringType.V4)

    @field_validator("base_score")
    @classmethod
    def validate_base_score_precision(cls, v: float) -> float:
        """Validate base score precision (must be multiple of 0.1)"""
        if round(v, 1) != v:
            raise ValueError("Base score must be a multiple of 0.1")
        return v

    @field_validator("threat_score")
    @classmethod
    def validate_threat_score_precision(cls, v: Optional[float]) -> Optional[float]:
        """Validate threat score precision (must be multiple of 0.1)"""
        if v is not None and round(v, 1) != v:
            raise ValueError("Threat score must be a multiple of 0.1")
        return v

    @field_validator("environmental_score")
    @classmethod
    def validate_environmental_score_precision(
        cls, v: Optional[float]
    ) -> Optional[float]:
        """Validate environmental score precision (must be multiple of 0.1)"""
        if v is not None and round(v, 1) != v:
            raise ValueError("Environmental score must be a multiple of 0.1")
        return v

    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        extra="forbid",
    )
