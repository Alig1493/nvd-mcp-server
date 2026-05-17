"""
Models for NVD CVE History API version 2.0

Based on the JSON Schema from NIST CSRC
Schema ID: https://csrc.nist.gov/schema/nvd/api/2.0/history_api_json_2.0.schema
"""

import re
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Detail(BaseModel):
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

    model_config = ConfigDict(extra="forbid")


class ChangeItem(BaseModel):
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

    model_config = ConfigDict(extra="forbid")


class DefChange(BaseModel):
    """
    Definition change model representing a wrapper for a change item

    This model wraps a single change item as part of the API response structure.
    """

    change: ChangeItem = Field(description="The CVE change item")

    model_config = ConfigDict(extra="forbid")


class NvdCveHistoryResponse(BaseModel):
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

    model_config = ConfigDict(extra="forbid", validate_assignment=True)
