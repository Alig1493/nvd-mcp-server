"""Base models for nvd data."""

import re
from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .cvss_v2 import CvssV2Model
from .cvss_v30 import CvssV30Model
from .cvss_v31 import CvssV31Model
from .cvss_v40 import CvssV40Model


class CveTagEnum(str, Enum):
    """Enumeration of possible CVE tag values for vulnerability categorization."""

    UNSUPPORTED_WHEN_ASSIGNED = "unsupported-when-assigned"
    EXCLUSIVELY_HOSTED_SERVICE = "exclusively-hosted-service"
    DISPUTED = "disputed"


class CvssTypeEnum(str, Enum):
    """Enumeration of CVSS metric types indicating primary or secondary assessment."""

    PRIMARY = "Primary"
    SECONDARY = "Secondary"


class OperatorEnum(str, Enum):
    """Enumeration of logical operators for configuration nodes."""

    AND = "AND"
    OR = "OR"


class LangString(BaseModel):
    """
    A language-specific string value used for internationalization.

    Attributes:
        lang: Language code (e.g., 'en', 'es', 'fr')
        value: The actual string content (max 4096 characters)
    """

    model_config = ConfigDict(populate_by_name=True)

    lang: str
    value: str = Field(max_length=4096)


class Reference(BaseModel):
    """
    External reference URL with optional source and tags.

    Attributes:
        url: The reference URL (max 500 characters, must be valid HTTP/HTTPS/FTP)
        source: Optional source identifier
        tags: Optional list of tags categorizing the reference
    """

    model_config = ConfigDict(populate_by_name=True)

    url: str = Field(max_length=500, pattern=r"^(ftp|http)s?://\S+$")
    source: Optional[str] = None
    tags: Optional[List[str]] = None


class VendorComment(BaseModel):
    """
    Comment provided by a vendor regarding a vulnerability.

    Attributes:
        organization: The vendor/organization name
        comment: The comment text
        last_modified: When the comment was last modified
    """

    model_config = ConfigDict(populate_by_name=True)

    organization: str
    comment: str
    last_modified: datetime = Field(alias="lastModified")


class Weakness(BaseModel):
    """
    Weakness classification for a vulnerability (e.g., CWE).

    Attributes:
        source: The source of the weakness classification
        type: The type of weakness classification
        description: List of language-specific descriptions
    """

    model_config = ConfigDict(populate_by_name=True)

    source: str
    type: str
    description: List[LangString]


class CpeMatch(BaseModel):
    """
    Common Platform Enumeration (CPE) match criteria for vulnerability applicability.

    Attributes:
        vulnerable: Whether this CPE match represents a vulnerable configuration
        criteria: The CPE match string
        match_criteria_id: Unique identifier for this match criteria
        version_start_excluding: Start version (exclusive) for version range
        version_start_including: Start version (inclusive) for version range
        version_end_excluding: End version (exclusive) for version range
        version_end_including: End version (inclusive) for version range
    """

    model_config = ConfigDict(populate_by_name=True)

    vulnerable: bool
    criteria: str
    match_criteria_id: UUID = Field(alias="matchCriteriaId")
    version_start_excluding: Optional[str] = Field(None, alias="versionStartExcluding")
    version_start_including: Optional[str] = Field(None, alias="versionStartIncluding")
    version_end_excluding: Optional[str] = Field(None, alias="versionEndExcluding")
    version_end_including: Optional[str] = Field(None, alias="versionEndIncluding")


class Node(BaseModel):
    """
    Configuration node defining logical relationships between CPE matches.

    Attributes:
        operator: Logical operator (AND/OR) for combining CPE matches
        negate: Whether to negate the result of this node
        cpe_match: List of CPE match criteria
    """

    model_config = ConfigDict(populate_by_name=True)

    operator: OperatorEnum
    negate: Optional[bool] = None
    cpe_match: List[CpeMatch] = Field(alias="cpeMatch")


class VulnConfig(BaseModel):
    """
    Configuration defining the applicability of a vulnerability.

    Attributes:
        operator: Optional logical operator for combining nodes
        negate: Whether to negate the result of this configuration
        nodes: List of configuration nodes
    """

    model_config = ConfigDict(populate_by_name=True)

    operator: Optional[OperatorEnum] = None
    negate: Optional[bool] = None
    nodes: List[Node]


class CvssV2(BaseModel):
    """
    CVSS version 2.0 scoring metrics for a vulnerability.

    Attributes:
        source: The source of the CVSS assessment
        type: Whether this is a primary or secondary assessment
        cvss_data: The CVSS v2.0 data structure
        base_severity: Base severity rating
        exploitability_score: Exploitability subscore (0-10)
        impact_score: Impact subscore (0-10)
        ac_insuf_info: Whether access complexity information is insufficient
        obtain_all_privilege: Whether all privileges can be obtained
        obtain_user_privilege: Whether user privileges can be obtained
        obtain_other_privilege: Whether other privileges can be obtained
        user_interaction_required: Whether user interaction is required
    """

    model_config = ConfigDict(populate_by_name=True)

    source: str
    type: CvssTypeEnum
    cvss_data: CvssV2Model = Field(alias="cvssData")
    base_severity: Optional[str] = Field(None, alias="baseSeverity")
    exploitability_score: Optional[float] = Field(
        None, ge=0, le=10, alias="exploitabilityScore"
    )
    impact_score: Optional[float] = Field(None, ge=0, le=10, alias="impactScore")
    ac_insuf_info: Optional[bool] = Field(None, alias="acInsufInfo")
    obtain_all_privilege: Optional[bool] = Field(None, alias="obtainAllPrivilege")
    obtain_user_privilege: Optional[bool] = Field(None, alias="obtainUserPrivilege")
    obtain_other_privilege: Optional[bool] = Field(None, alias="obtainOtherPrivilege")
    user_interaction_required: Optional[bool] = Field(
        None, alias="userInteractionRequired"
    )


class CvssV30(BaseModel):
    """
    CVSS version 3.0 scoring metrics for a vulnerability.

    Attributes:
        source: The source of the CVSS assessment
        type: Whether this is a primary or secondary assessment
        cvss_data: The CVSS v3.0 data structure
        exploitability_score: Exploitability subscore (0-10)
        impact_score: Impact subscore (0-10)
    """

    model_config = ConfigDict(populate_by_name=True)

    source: str
    type: CvssTypeEnum
    cvss_data: CvssV30Model = Field(alias="cvssData")
    exploitability_score: Optional[float] = Field(
        None, ge=0, le=10, alias="exploitabilityScore"
    )
    impact_score: Optional[float] = Field(None, ge=0, le=10, alias="impactScore")


class CvssV31(BaseModel):
    """
    CVSS version 3.1 scoring metrics for a vulnerability.

    Attributes:
        source: The source of the CVSS assessment
        type: Whether this is a primary or secondary assessment
        cvss_data: The CVSS v3.1 data structure
        exploitability_score: Exploitability subscore (0-10)
        impact_score: Impact subscore (0-10)
    """

    model_config = ConfigDict(populate_by_name=True)

    source: str
    type: CvssTypeEnum
    cvss_data: CvssV31Model = Field(alias="cvssData")
    exploitability_score: Optional[float] = Field(
        None, ge=0, le=10, alias="exploitabilityScore"
    )
    impact_score: Optional[float] = Field(None, ge=0, le=10, alias="impactScore")


class CvssV40(BaseModel):
    """
    CVSS version 4.0 scoring metrics for a vulnerability.

    Attributes:
        source: The source of the CVSS assessment
        type: Whether this is a primary or secondary assessment
        cvss_data: The CVSS v4.0 data structure
    """

    model_config = ConfigDict(populate_by_name=True)

    source: str
    type: CvssTypeEnum
    cvss_data: CvssV40Model = Field(alias="cvssData")


class Metrics(BaseModel):
    """
    Container for various CVSS scoring metrics across different versions.

    Attributes:
        cvss_metric_v40: List of CVSS v4.0 metrics
        cvss_metric_v31: List of CVSS v3.1 metrics
        cvss_metric_v30: List of CVSS v3.0 metrics
        cvss_metric_v2: List of CVSS v2.0 metrics
    """

    model_config = ConfigDict(populate_by_name=True)

    cvss_metric_v40: Optional[List[CvssV40]] = Field(None, alias="cvssMetricV40")
    cvss_metric_v31: Optional[List[CvssV31]] = Field(None, alias="cvssMetricV31")
    cvss_metric_v30: Optional[List[CvssV30]] = Field(None, alias="cvssMetricV30")
    cvss_metric_v2: Optional[List[CvssV2]] = Field(None, alias="cvssMetricV2")


class CveTag(BaseModel):
    """
    Tag information for a CVE indicating special characteristics.

    Attributes:
        source_identifier: Email address or UUID of the source that
            contributed the information
        tags: List of tags categorizing the CVE
    """

    model_config = ConfigDict(populate_by_name=True)

    source_identifier: str = Field(
        alias="sourceIdentifier",
        description=(
            "The email address or UUID of the source that contributed the information"
        ),
    )
    tags: List[CveTagEnum]


class CveItem(BaseModel):
    """
    Complete CVE (Common Vulnerabilities and Exposures) item with all associated data.

    Attributes:
        id: CVE identifier (format: CVE-YYYY-NNNN)
        source_identifier: Identifier of the source that submitted the CVE
        vuln_status: Current status of the vulnerability
        published: Date and time when the CVE was published
        last_modified: Date and time when the CVE was last modified
        evaluator_comment: Optional comment from the evaluator
        evaluator_solution: Optional solution from the evaluator
        evaluator_impact: Optional impact assessment from the evaluator
        cisa_exploit_add: Date when CISA added this to the Known Exploited
        Vulnerabilities catalog
        cisa_action_due: Date when CISA action is due
        cisa_required_action: Required action as specified by CISA
        cisa_vulnerability_name: Vulnerability name as specified by CISA
        cve_tags: List of tags associated with this CVE
        descriptions: List of language-specific descriptions
        references: List of external references
        metrics: CVSS scoring metrics
        weaknesses: List of associated weaknesses (e.g., CWE)
        configurations: List of vulnerable configurations
        vendor_comments: Comments from vendors
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    source_identifier: Optional[str] = Field(None, alias="sourceIdentifier")
    vuln_status: Optional[str] = Field(None, alias="vulnStatus")
    published: datetime
    last_modified: datetime = Field(alias="lastModified")
    evaluator_comment: Optional[str] = Field(None, alias="evaluatorComment")
    evaluator_solution: Optional[str] = Field(None, alias="evaluatorSolution")
    evaluator_impact: Optional[str] = Field(None, alias="evaluatorImpact")
    cisa_exploit_add: Optional[str] = Field(None, alias="cisaExploitAdd")
    cisa_action_due: Optional[str] = Field(None, alias="cisaActionDue")
    cisa_required_action: Optional[str] = Field(None, alias="cisaRequiredAction")
    cisa_vulnerability_name: Optional[str] = Field(None, alias="cisaVulnerabilityName")
    cve_tags: Optional[List[CveTag]] = Field(None, alias="cveTags")
    descriptions: List[LangString] = Field(min_length=1)
    references: List[Reference]
    metrics: Optional[Metrics] = None
    weaknesses: Optional[List[Weakness]] = None
    configurations: Optional[List[VulnConfig]] = None
    vendor_comments: Optional[List[VendorComment]] = Field(None, alias="vendorComments")

    @field_validator("id")
    @classmethod
    def validate_cve_id(cls, v: str) -> str:
        if not re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", v):
            raise ValueError("CVE ID must match pattern CVE-YYYY-NNNN")
        return v


class DefCveItem(BaseModel):
    """
    Wrapper for CVE item as defined in the NVD API response structure.

    Attributes:
        cve: The CVE item containing all vulnerability data
    """

    model_config = ConfigDict(populate_by_name=True)

    cve: CveItem


class NvdVulnerabilityData(BaseModel):
    """
    Root model representing a complete NVD (National Vulnerability Database)
    API response.

    This model contains pagination information and a list of vulnerabilities returned
    by the NVD Vulnerability Data API version 2.2.2.

    Attributes:
        results_per_page: Number of results returned per page
        start_index: Starting index for this page of results
        total_results: Total number of results available
        format: Response format (typically "NVD_CVE")
        version: API version (e.g., "2.2.2")
        timestamp: Timestamp when the response was generated
        vulnerabilities: List of vulnerability items
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )

    results_per_page: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    format: str
    version: str
    timestamp: datetime
    vulnerabilities: List[DefCveItem]
