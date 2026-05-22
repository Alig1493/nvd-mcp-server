"""
Models for NVD CVE History API version 2.0

Based on the JSON Schema from NIST CSRC
Schema ID: https://csrc.nist.gov/schema/nvd/api/2.0/history_api_json_2.0.schema

 The CVE Change History API is used to easily retrieve information on changes made
 to a single CVE or a collection of CVE from the NVD. This API provides additional
 transparency to the work of the NVD, allowing users to easily monitor
 when and why vulnerabilities change.

The NVD has existed in some form since 1999 and the fidelity of this information
has changed several times over the decades. Earlier records may not contain the
level of detail available with more recent CVE records.
This is most apparent on CVE records prior to 2015.

"""

import re
from datetime import datetime
from enum import StrEnum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventName(StrEnum):
    CVE_RECEIVED = "CVE Received"
    INITIAL_ANALYSIS = "Initial Analysis"
    REANALYSIS = "Reanalysis"
    CVE_MODIFIED = "CVE Modified"
    MODIFIED_ANALYSIS = "Modified Analysis"
    CVE_TRANSLATED = "CVE Translated"
    VENDOR_COMMENT = "Vendor Comment"
    CVE_SOURCE_UPDATE = "CVE Source Update"
    CPE_DEPRECATION_REMAP = "CPE Deprecation Remap"
    CWE_REMAP = "CWE Remap"
    REFERENCE_TAG_UPDATE = "Reference Tag Update"
    CVE_REJECTED = "CVE Rejected"
    CVE_UNREJECTED = "CVE Unrejected"
    CVE_CISA_KEV_UPDATE = "CVE CISA KEV Update"
    DATA_REMEDIATION = "Data Remediation"
    CVE_STATUS_CHANGE = "CVE Status Change"


class BaseModelExtrForbid(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_by_name=True)


class Detail(BaseModelExtrForbid):
    """
    Detail model representing a specific change detail within a CVE change event

    Contains information about what was changed, including the type of change
    and optionally the old and new values.
    """

    type: str = Field(description="Type of change that occurred")

    action: Optional[str] = Field(default=None, description="Action that was performed")

    old_value: Optional[str] = Field(
        default=None, alias="oldValue", description="Previous value before the change"
    )

    new_value: Optional[str] = Field(
        default=None, alias="newValue", description="New value after the change"
    )

    def to_summary(self) -> str:
        """Convert detail elements to a summary."""
        change_str = ""
        if self.old_value:
            change_str = f"from {self.old_value}"
        return (
            f"Change type: {self.type}, change action: {self.action}, "
            f"{change_str} to {self.new_value}."
        )


class ChangeItem(BaseModelExtrForbid):
    """
    Change item model representing a single CVE change event

    Contains information about when and what changed for a specific CVE,
    including the source of the change and detailed change information.
    """

    cve_id: str = Field(
        alias="cveId", description="CVE identifier in the format CVE-YYYY-NNNN"
    )

    event_name: str = Field(
        alias="eventName", description="Name of the event that triggered this change"
    )

    cve_change_id: UUID = Field(
        alias="cveChangeId", description="Unique identifier for this CVE change event"
    )

    source_identifier: str = Field(
        alias="sourceIdentifier",
        description="Identifier of the source that made this change",
    )

    created: Optional[datetime] = Field(
        default=None, description="Timestamp when this change was created"
    )

    details: Optional[List[Detail]] = Field(
        default=None, description="List of detailed changes within this change event"
    )

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id_format(cls, v: str) -> str:
        """Validate CVE ID format (CVE-YYYY-NNNN where NNNN is 4 or more digits)"""
        pattern = r"^CVE-[0-9]{4}-[0-9]{4,}$"
        if not re.match(pattern, v):
            raise ValueError(
                "CVE ID must be in format CVE-YYYY-NNNN where NNNN is 4 or more digits"
            )
        return v


class DefChange(BaseModelExtrForbid):
    """
    Definition change model representing a wrapper for a change item

    This model wraps a single change item as part of the API response structure.
    """

    change: ChangeItem = Field(description="The CVE change item")


class NvdCveHistoryResponse(BaseModelExtrForbid):
    """
    NVD CVE History API 2.0 response model

    Represents the complete response from the NVD CVE History API, including
    pagination information and an array of CVE changes.
    """

    results_per_page: int = Field(
        alias="resultsPerPage", description="Number of results returned per page"
    )

    start_index: int = Field(
        alias="startIndex", description="Starting index of the results"
    )

    total_results: int = Field(
        alias="totalResults", description="Total number of results available"
    )

    format: str = Field(description="Format of the response data")

    version: str = Field(description="Version of the API")

    timestamp: datetime = Field(description="Timestamp when the response was generated")

    cve_changes: Optional[List[DefChange]] = Field(
        default=None, alias="cveChanges", description="Array of CVE changes"
    )


class NvdCveHistoryRequest(BaseModelExtrForbid):
    """
    NVD CVE History API 2.0 request model.

    The CVE Change History API is used to easily retrieve information
    on changes made to a single CVE or a collection of CVE from the NVD.
    This API provides additional transparency to the work of the NVD,
    allowing users to easily monitor when and why vulnerabilities change.

    The NVD has existed in some form since 1999 and the fidelity of this
    information has changed several times over the decades. Earlier records
    may not contain the level of detail available with more recent CVE records.
    This is most apparent on CVE records prior to 2015.
    """

    change_start_date: datetime | None = Field(
        default=None,
        alias="changeStartDate",
        description="""
            These parameters return any CVE that changed during the specified period.
            Please note, this is different from the last modified date parameters used
            with other APIs. If filtering by the change date, both changeStartDate and
            changeEndDate are required. The maximum allowable range when using any date
            range parameters is 120 consecutive days.
        """,
        examples=[
            "https://services.nvd.nist.gov/rest/json/cvehistory/2.0/"
            "?changeStartDate=2021-08-04T13:00:00.000%2B01:00"
            "&changeEndDate=2021-10-22T13:36:00.000%2B01:00"
        ],
    )
    end_date: datetime | None = Field(default=None, alias="changeEndDate")
    cve_id: str | None = Field(
        default=None,
        alias="cveId",
        description="""
            This parameter returns the complete change history for a specific
            vulnerability identified by its unique Common Vulnerabilities and
            Exposures identifier (the CVE ID). cveId will not accept {CVE-ID}
            for vulnerabilities not yet published in the NVD.
        """,
        examples=[
            "https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-2019-1010218"
        ],
    )
    event_name: EventName | None = Field(
        default=None,
        alias="eventName",
        description="""
            This parameter returns all CVE associated with a specific type of
            change event. Please note, each request can contain only one value
            for the eventName parameter. Empty spaces in the URL should be encoded
            in the request as "%20".
            The user agent may handle this encoding automatically.
        """,
        examples=[
            "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
            "?eventName=CVE%20Rejected"
            "&changeStartDate=2021-08-04T13:00:00.000%2B01:00"
            "&changeEndDate=2021-10-22T13:36:00.000%2B01:00"
        ],
    )
    results_per_page: int | None = Field(
        default=10,
        alias="resultsPerPage",
        description="""
            This parameter specifies the maximum number of change events
            to be returned in a single API response. For network considerations,
            the default value and maximum allowable limit is 5,000.
        """,
        examples=[
            "https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?resultsPerPage=20&startIndex=0"
        ],
    )
    start_index: int | None = Field(
        default=0,
        alias="startIndex",
        description="""
             This parameter specifies the index of the first change events
             to be returned in the response data. The index is zero-based,
             meaning the first change events is at index zero.
        """,
        examples=[
            "https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?resultsPerPage=20&startIndex=0"
        ],
    )
