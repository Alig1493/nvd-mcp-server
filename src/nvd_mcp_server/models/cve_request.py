"""Input models for NVD CVE API requests."""

import enum
import logging
import re
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

logger = logging.getLogger(__name__)


class CveTag(enum.StrEnum):
    """CVE tag types."""

    DISPUTED = "disputed"
    UNSUPPORTED_WHEN_ASSIGNED = "unsupported-when-assigned"
    EXCLUSIVELY_HOSTED_SERVICE = "exclusively-hosted-service"


class CVSSV2Severity(enum.StrEnum):
    """CVSS Severity types."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CVSSV3Severity(enum.StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CVSSV4Severity(enum.StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VersionType(enum.StrEnum):
    """Version boundary types."""

    INCLUDING = "including"
    EXCLUDING = "excluding"


class CVERequest(BaseModel):
    """
    Pydantic model for request params validation.

    Please note, as of July 2022, the NVD no longer generates
    new information for CVSS v2. Existing CVSS v2 information will
    remain in the database but the NVD will no longer actively populate
    CVSS v2 for new CVEs. NVD analysts will continue to use the reference
    information provided with the CVE and any publicly available information
    at the time of analysis to associate Reference Tags, information related
    to CVSS v3.1, CWE, and CPE Applicability statements.

    The CVE API returns four primary objects in the response body that are used
    for pagination: resultsPerPage, startIndex, totalResults, and vulnerabilities.
    totalResults indicates the total number of CVE records that match the request
    parameters. If the value of totalResults is greater than the value of
    resultsPerPage, there are more records than could be returned by a single API
    response and additional requests must update the startIndex to get the remaining
    records.

    The best, most efficient, practice for keeping up to date with the NVD is to use
    the date range parameters to request only the CVEs that have been modified since
    your last request.

    If filtering by `isVulnerable`, `cpeName` is required.
    Please note, `virtualMatchString` is not accepted in requests that use
    `isVulnerable`.
    """

    cpe_name: str | None = Field(
        None,
        description=(
            "This parameter returns all CVE associated with a specific CPE. "
            "The exact value provided with cpeName is compared against the CPE "
            "Match Criteria within a CVE applicability statement. A CPE Name is "
            "a string of 13 colon separated values that describe a product. "
            "In CPEv2.3 the first two values are always 'cpe' and '2.3'. "
            "When filtering by cpeName the part, vendor, product, and version "
            "components are required to contain values other than '*'."
        ),
        serialization_alias="cpeName",
        examples=[
            "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
        ],
    )
    cve_id: str | None = Field(
        None,
        description=(
            "This parameter returns a specific vulnerability "
            "identified by its unique Common Vulnerabilities "
            "and Exposures identifier (the CVE ID). cveId will "
            "not accept {CVE-ID} for vulnerabilities not yet published in the NVD. "
        ),
        serialization_alias="cveId",
        examples=["CVE-2019-1010218"],
    )
    cve_tag: CveTag | None = Field(
        None,
        description=(
            "This parameter returns only the CVE "
            "records that include the provided cveTag."
        ),
        serialization_alias="cveTag",
        examples=["disputed"],
    )
    cvss_v2_metrics: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that match the provided "
            "{CVSSv2 vector string}. Either full or partial vector strings may be used."
            " This parameter cannot be used in requests that include cvssV3Metrics "
            "or cvssv4Metrics. "
        ),
        serialization_alias="cvssV2Metrics",
        examples=["AV:N/AC:H/Au:N/C:C/I:C/A:C"],
    )
    cvss_v2_severity: CVSSV2Severity | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that match the provided "
            "CVSSv2 qualitative severity rating. This parameter cannot be "
            "used in requests that include cvssV3Severity or cvssv4Severity. "
        ),
        serialization_alias="cvssV2Severity",
        examples=["LOW"],
    )
    cvss_v3_metrics: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that match the provided "
            "{CVSSv3 vector string}. Either full or partial vector strings may "
            "be used. This parameter cannot be used in requests that include "
            "cvssV2Metrics or cvssv4Metrics. "
        ),
        serialization_alias="cvssV3Metrics",
        examples=["AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L"],
    )
    cvss_v3_severity: CVSSV3Severity | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that match the provided CVSSv3 "
            "qualitative severity rating. This parameter cannot be used in requests "
            "that include cvssV2Severity or cvssv4Severity."
            "Note: The NVD will not contain CVSS v3 vector strings with a severity "
            "of NONE. This is why that severity is not an included option. "
        ),
        serialization_alias="cvssV3Severity",
        examples=["CRITICAL"],
    )
    cvss_v4_metrics: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that match the provided "
            "{CVSSv4 vector string}. Either full or partial vector strings "
            "may be used. This parameter cannot be used in requests that include "
            "cvssV2Metrics or cvssV3Severity. "
        ),
        serialization_alias="cvssV4Metrics",
        examples=["AV:A/AC:H/PR:H/UI:N"],
    )
    cvss_v4_severity: CVSSV4Severity | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that match the provided CVSSv4 "
            "qualitative severity rating. This parameter cannot be used in requests "
            "that include cvssV2Severity or cvssV3Severity."
            "Note: The NVD enrichment data will not contain CVSS v4 vector strings "
            "with a severity of NONE. "
            "This is why that severity is not an included option."
        ),
        serialization_alias="cvssV4Severity",
        examples=["CRITICAL"],
    )
    cwe_id: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVE that include a weakness "
            "identified by Common Weakness Enumeration using the provided {CWE-ID}. "
            "Note: The NVD also makes use of two placeholder "
            "CWE-ID values NVD-CWE-Other and NVD-CWE-noinfo which can also be used. "
        ),
        serialization_alias="cweId",
    )
    has_cert_alerts: bool | None = Field(
        None,
        description=(
            "This parameter returns the CVE that contain a "
            "Technical Alert from US-CERT. "
            "Please note, this parameter is provided without a parameter value. "
            "Append `hasCertAlerts` to the end of the `nvd_cve_url`."
        ),
        serialization_alias="hasCertAlerts",
    )
    has_cert_notes: bool | None = Field(
        None,
        description=(
            "This parameter returns the CVE that contain a "
            "Vulnerability Note from CERT/CC."
            "Please note, this parameter is provided without a parameter value."
        ),
        serialization_alias="hasCertNotes",
    )
    has_kev: bool | None = Field(
        None,
        description=(
            "This parameter returns the CVE that appear in CISA's "
            "Known Exploited Vulnerabilities (KEV) Catalog. "
            "Please note, this parameter is provided without a parameter value."
        ),
        serialization_alias="hasKev",
    )
    has_oval: bool | None = Field(
        None,
        description=(
            "This parameter returns the CVE that contain information from MITRE's "
            "Open Vulnerability and Assessment Language (OVAL) before this "
            "transitioned to the Center for Internet Security (CIS). "
            "Please note, this parameter is provided without a parameter value."
        ),
        serialization_alias="hasOval",
    )
    is_vulnerable: bool | None = Field(
        None,
        serialization_alias="isVulnerable",
        examples=["cpe:2.3:o:microsoft:windows_10:1607 with isVulnerable flag"],
    )
    no_rejected: bool | None = Field(
        None,
        description=(
            "By default, the CVE API includes CVE records with the REJECT or Rejected "
            "status. This parameter excludes CVE records with the REJECT or Rejected "
            "status from API response. Please note, this parameter is provided without "
            "a parameter value. "
        ),
        serialization_alias="noRejected",
    )
    kev_start_date: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that were added to the CISA "
            "Known Exploited Vulnerabilities (KEV) catalog during the specified "
            "period. When filtering by KEV inclusion dates, both kevStartDate and "
            "kevEndDate are required. Values must be entered in the extended "
            'ISO-8601 date/time format: [YYYY]["-"][MM]["-"][DD]["T"]'
            '[HH][":"][MM][":"][SS][Z]'
        ),
        serialization_alias="kevStartDate",
    )
    kev_end_date: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that were added to the CISA "
            "Known Exploited Vulnerabilities (KEV) catalog during the specified "
            "period. When filtering by KEV inclusion dates, both kevStartDate and "
            "kevEndDate are required. Values must be entered in the extended "
            'ISO-8601 date/time format: [YYYY]["-"][MM]["-"][DD]["T"]'
            '[HH][":"][MM][":"][SS][Z]'
        ),
        serialization_alias="kevEndDate",
    )
    last_mod_start_date: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that were last modified during "
            "the specified period. If filtering by the last modified date, both "
            "lastModStartDate and lastModEndDate are required. The maximum "
            "allowable range when using any date range parameters is 120 "
            "consecutive days. Values must be entered in the extended ISO-8601 "
            'date/time format: [YYYY]["-"][MM]["-"][DD]["T"][HH][":"]'
            '[MM][":"][SS][Z]'
        ),
        serialization_alias="lastModStartDate",
        examples=["2021-08-04T13:00:00.000+01:00"],
    )
    last_mod_end_date: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that were last modified during "
            "the specified period. If filtering by the last modified date, both "
            "lastModStartDate and lastModEndDate are required. The maximum "
            "allowable range when using any date range parameters is 120 "
            "consecutive days. Values must be entered in the extended ISO-8601 "
            'date/time format: [YYYY]["-"][MM]["-"][DD]["T"][HH][":"]'
            '[MM][":"][SS][Z]'
        ),
        serialization_alias="lastModEndDate",
        examples=["2021-10-22T13:36:00.000+01:00"],
    )
    pub_start_date: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that were added to the NVD "
            "(i.e., published) during the specified period. If filtering by the "
            "published date, both pubStartDate and pubEndDate are required. The "
            "maximum allowable range when using any date range parameters is 120 "
            "consecutive days. Values must be entered in the extended ISO-8601 "
            'date/time format: [YYYY]["-"][MM]["-"][DD]["T"][HH][":"]'
            '[MM][":"][SS][Z]'
        ),
        serialization_alias="pubStartDate",
        examples=["2021-08-04T00:00:00.000"],
    )
    pub_end_date: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs that were added to the NVD "
            "(i.e., published) during the specified period. If filtering by the "
            "published date, both pubStartDate and pubEndDate are required. The "
            "maximum allowable range when using any date range parameters is 120 "
            "consecutive days. Values must be entered in the extended ISO-8601 "
            'date/time format: [YYYY]["-"][MM]["-"][DD]["T"][HH][":"]'
            '[MM][":"][SS][Z]'
        ),
        serialization_alias="pubEndDate",
        examples=["2021-10-22T00:00:00.000"],
    )
    source_identifier: str | None = Field(
        None,
        description=(
            "This parameter returns CVE where the exact value of sourceIdentifier "
            "appears as a data source in the CVE record. The CVE API returns "
            "sourceIdentifier values within the descriptions object. The Source API "
            "returns detailed information on the organizations that provide the data "
            "contained in the NVD dataset, including every valid sourceIdentifier "
            "value."
        ),
        serialization_alias="sourceIdentifier",
        examples=["cve@mitre.org"],
    )
    version_end: str | None = Field(
        None,
        description=(
            "The virtualMatchString parameter may be combined with versionEnd and "
            "versionEndType to return only the CVEs associated with CPEs in specific "
            "version ranges. If filtering by the ending version, versionEnd, "
            "versionEndType, and virtualMatchString are required. Requests that "
            "include versionEnd cannot include a version component in the "
            "virtualMatchString."
        ),
        serialization_alias="versionEnd",
    )
    version_end_type: VersionType | None = Field(
        None,
        description=(
            "The virtualMatchString parameter may be combined with versionEnd and "
            "versionEndType to return only the CVEs associated with CPEs in specific "
            "version ranges. If filtering by the ending version, versionEnd, "
            "versionEndType, and virtualMatchString are required."
        ),
        serialization_alias="versionEndType",
    )
    version_start: str | None = Field(
        None,
        description=(
            "The virtualMatchString parameter may be combined with versionStart and "
            "versionStartType to return only the CVEs associated with CPEs in specific "
            "version ranges. If filtering by the starting version, versionStart, "
            "versionStartType, and virtualMatchString are required. Requests that "
            "include versionStart cannot include a version component in the "
            "virtualMatchString."
        ),
        serialization_alias="versionStart",
    )
    version_start_type: VersionType | None = Field(
        None,
        description=(
            "The virtualMatchString parameter may be combined with versionStart and "
            "versionStartType to return only the CVEs associated with CPEs in specific "
            "version ranges. If filtering by the starting version, versionStart, "
            "versionStartType, and virtualMatchString are required."
        ),
        serialization_alias="versionStartType",
    )
    virtual_match_string: str | None = Field(
        None,
        description=(
            "This parameter filters CVE more broadly than cpeName. The exact value "
            "is compared against the CPE Match Criteria present on CVE applicability "
            "statements. Unlike a CPE Name, match strings do not require a value in "
            "the part, vendor, product, or version components. CPE Match String Ranges "
            "are only supported for the version component when virtualMatchString is "
            "combined with versionStart/versionEnd parameters. When both cpeName and "
            "virtualMatchString are provided, only the cpeName is used."
        ),
        serialization_alias="virtualMatchString",
        examples=["cpe:2.3:*:*:*:*:*:*:de"],
    )
    keyword_exact_match: bool | None = Field(
        None,
        description=(
            "When keywordSearch is used along with keywordExactMatch, "
            "the API will return only the CVEs matching the exact phrase. "
            "Requires keywordSearch to be set."
        ),
        serialization_alias="keywordExactMatch",
    )
    keyword_search: str | None = Field(
        None,
        description=(
            "This parameter returns only the CVEs where a word or phrase is found "
            "in the current description. Multiple keywords are separated by a space. "
        ),
        serialization_alias="keywordSearch",
        examples=["Microsoft Outlook", "Windows MacOs Linux"],
    )

    # Return results config params
    results_per_page: int = Field(
        default=10,
        description=(
            "This parameter specifies the maximum number of CVE records "
            "to be returned in a single API response. For network considerations, "
            "the default value and maximum allowable limit is 2,000. "
        ),
        serialization_alias="resultsPerPage",
    )
    start_index: int = Field(
        default=0,
        description=(
            "This parameter specifies the index of the first CVE to be returned "
            "in the response data. The index is zero-based, meaning the first CVE "
            "is at index zero. "
        ),
        serialization_alias="startIndex",
    )
    model_config = ConfigDict(serialize_by_alias=True)

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, v: str | None) -> str | None:
        """Validate and sanitize CVE ID format."""
        if v is None:
            return v
        sanitized = v.strip().upper()
        cve_pattern = r"^CVE-\d{4}-\d{4,}$"
        if not re.match(cve_pattern, sanitized):
            raise ValueError(
                "Invalid CVE ID format. Expected format: CVE-YYYY-NNNN "
                "(e.g., CVE-2021-1234)."
            )
        return sanitized

    @field_validator("cvss_v2_metrics", "cvss_v3_metrics", "cvss_v4_metrics")
    @classmethod
    def validate_cvss_metrics(cls, v: str | None) -> str | None:
        """
        Validate CVSS metrics filter parameter format.

        The NVD API accepts abbreviated, partial vector strings without a
        version prefix (e.g. 'AV:N/AC:L/PR:N'). Full or partial vectors
        are both valid. This validator checks the structural shape only.
        """
        if v is None:
            return v
        # Each component is KEY:VALUE, separated by /
        if not re.match(r"^[A-Za-z]+:[A-Za-z0-9]+(/[A-Za-z]+:[A-Za-z0-9]+)*$", v):
            raise ValueError(
                "Invalid CVSS metrics format. Expected KEY:VALUE pairs separated "
                "by '/' (e.g. 'AV:N/AC:L/PR:N'). No version prefix required."
            )
        return v

    @field_validator(
        "kev_start_date",
        "kev_end_date",
        "last_mod_start_date",
        "last_mod_end_date",
        "pub_start_date",
        "pub_end_date",
    )
    @classmethod
    def validate_iso_dates(cls, v: str | None) -> str | None:
        """Validate date format according to extended ISO-8601."""
        if v is None:
            return v

        iso_pattern = (
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?"
            r"([Z]|[+-]\d{2}:\d{2}|%2B\d{2}:\d{2})?$"
        )

        if not re.match(iso_pattern, v):
            raise ValueError(
                "Invalid date format. Expected extended ISO-8601 format: "
                "YYYY-MM-DDTHH:MM:SS[.sss][Z|±HH:MM] "
                "(e.g., 2023-01-01T00:00:00Z or 2021-08-04T13:00:00.000+01:00)."
            )

        return v

    @field_validator("cpe_name")
    @classmethod
    def validate_cpe_name(cls, v: str | None) -> str | None:
        """Validate CPE name format according to CPEv2.3 specification."""
        if v is None:
            return v

        components = v.split(":")

        if len(components) < 6:
            raise ValueError(
                "Invalid CPE format. Must have at least 6 components: "
                "cpe:2.3:part:vendor:product:version."
            )

        if components[0] != "cpe" or components[1] != "2.3":
            raise ValueError("Invalid CPE format. Must start with 'cpe:2.3'.")

        part, vendor, product, version = components[2:6]
        if part == "*" or vendor == "*" or product == "*" or version == "*":
            raise ValueError(
                "CPE part, vendor, product, and version components cannot be '*'. "
                "These components are required to contain values other than '*'."
            )

        return v

    @field_validator("virtual_match_string")
    @classmethod
    def validate_virtual_match_string(cls, v: str | None) -> str | None:
        """Validate virtual match string format according to CPE specification."""
        if v is None:
            return v

        components = v.split(":")

        if len(components) < 3:
            raise ValueError(
                "Invalid virtual match string format. Must start with 'cpe:2.3'."
            )

        if components[0] != "cpe" or components[1] != "2.3":
            raise ValueError(
                "Invalid virtual match string format. Must start with 'cpe:2.3'."
            )

        return v

    @model_validator(mode="after")
    def validate_version_range_and_cpe_constraints(self) -> Self:
        """Validate constraints between version range and CPE parameters."""

        has_version_start = (
            self.version_start is not None or self.version_start_type is not None
        )
        has_version_end = (
            self.version_end is not None or self.version_end_type is not None
        )
        has_virtual_match = self.virtual_match_string is not None
        has_cpe_name = self.cpe_name is not None

        if has_cpe_name and has_virtual_match:
            logger.warning(
                "Both `cpeName` and `virtualMatchString` provided. "
                "Only `cpeName` will be used, cpeName: %s, "
                "virtualMatchString will be ignored, virtualMatchString: %s.",
                self.cpe_name,
                self.virtual_match_string,
            )

        if (has_version_start or has_version_end) and not has_virtual_match:
            raise ValueError(
                "When using version range parameters (versionStart, "
                "versionStartType, versionEnd, versionEndType), "
                "virtualMatchString is required."
            )

        if (self.version_start is None) != (self.version_start_type is None):
            raise ValueError(
                "When filtering by starting version, both versionStart and "
                "versionStartType are required."
            )

        if (self.version_end is None) != (self.version_end_type is None):
            raise ValueError(
                "When filtering by ending version, both versionEnd and "
                "versionEndType are required."
            )

        if has_virtual_match and (has_version_start or has_version_end):
            virtual_match = self.virtual_match_string
            assert virtual_match is not None
            virtual_components = virtual_match.split(":")
            if (
                len(virtual_components) > 5
                and virtual_components[5]
                and virtual_components[5] != "*"
            ):
                raise ValueError(
                    "virtualMatchString cannot include a version component when "
                    "used with version range parameters (versionStart/versionEnd)."
                )

        if self.is_vulnerable is not None and self.cpe_name is None:
            raise ValueError("When filtering by isVulnerable, cpeName is required.")

        if self.is_vulnerable is not None and has_virtual_match:
            raise ValueError(
                "virtualMatchString is not accepted in requests that use isVulnerable."
            )

        return self

    @model_validator(mode="after")
    def validate_cvss_severity_exclusivity(self) -> "CVERequest":
        """Validate that only one CVSS severity parameter is used."""

        cvss_severity_count = sum(
            [
                self.cvss_v2_severity is not None,
                self.cvss_v3_severity is not None,
                self.cvss_v4_severity is not None,
            ]
        )

        if cvss_severity_count > 1:
            raise ValueError(
                "Only one of cvssV2Severity, cvssV3Severity or cvssV4Severity "
                "can be used. They cannot be used with each other."
            )

        return self

    @model_validator(mode="after")
    def validate_cvss_metrics_exclusivity(self) -> "CVERequest":
        """Validate that only one CVSS metrics parameter is used."""

        cvss_metrics_count = sum(
            [
                self.cvss_v2_metrics is not None,
                self.cvss_v3_metrics is not None,
                self.cvss_v4_metrics is not None,
            ]
        )

        if cvss_metrics_count > 1:
            raise ValueError(
                "Only one of cvssV2Metrics, cvssV3Metrics or cvssV4Metrics "
                "can be used. They cannot be used with each other."
            )

        return self
