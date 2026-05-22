from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING, Optional

from pydantic import BaseModel

from nvd_mcp_server.models.cve_history import NvdCveHistoryResponse

if TYPE_CHECKING:
    from .core import CveItem, NvdVulnerabilityData
    from .cve_history import DefChange


class CvssSummary(BaseModel):
    version: str
    score: float
    severity: str
    vector: str


class KevInfo(BaseModel):
    date_added: str
    due_date: Optional[str] = None
    required_action: Optional[str] = None


class CveSummary(BaseModel):
    id: str
    published: date
    last_modified: date
    status: Optional[str] = None
    description: str
    cvss: Optional[CvssSummary] = None
    cwes: list[str]
    references: list[str]
    kev: Optional[KevInfo] = None

    @classmethod
    def from_cve_item(cls, cve: CveItem) -> CveSummary:
        description = next((d.value for d in cve.descriptions if d.lang == "en"), "")

        cvss: CvssSummary | None = None
        m = cve.metrics
        if m:
            if m.cvss_metric_v40:
                p40 = next(
                    (x for x in m.cvss_metric_v40 if x.type == "Primary"),
                    m.cvss_metric_v40[0],
                )
                cvss = CvssSummary(
                    version="4.0",
                    score=p40.cvss_data.base_score,
                    severity=p40.cvss_data.base_severity,
                    vector=p40.cvss_data.vector_string,
                )
            elif m.cvss_metric_v31:
                p31 = next(
                    (x for x in m.cvss_metric_v31 if x.type == "Primary"),
                    m.cvss_metric_v31[0],
                )
                cvss = CvssSummary(
                    version="3.1",
                    score=p31.cvss_data.base_score,
                    severity=p31.cvss_data.base_severity,
                    vector=p31.cvss_data.vector_string,
                )
            elif m.cvss_metric_v30:
                p30 = next(
                    (x for x in m.cvss_metric_v30 if x.type == "Primary"),
                    m.cvss_metric_v30[0],
                )
                cvss = CvssSummary(
                    version="3.0",
                    score=p30.cvss_data.base_score,
                    severity=p30.cvss_data.base_severity,
                    vector=p30.cvss_data.vector_string,
                )
            elif m.cvss_metric_v2:
                p2 = next(
                    (x for x in m.cvss_metric_v2 if x.type == "Primary"),
                    m.cvss_metric_v2[0],
                )
                cvss = CvssSummary(
                    version="2.0",
                    score=p2.cvss_data.base_score,
                    severity=p2.base_severity or "",
                    vector=p2.cvss_data.vector_string,
                )

        cwes: list[str] = []
        if cve.weaknesses:
            for w in cve.weaknesses:
                for desc in w.description:
                    if desc.lang == "en" and desc.value not in cwes:
                        cwes.append(desc.value)

        kev: KevInfo | None = None
        if cve.cisa_exploit_add:
            kev = KevInfo(
                date_added=cve.cisa_exploit_add,
                due_date=cve.cisa_action_due,
                required_action=cve.cisa_required_action,
            )

        return cls(
            id=cve.id,
            published=cve.published.date(),
            last_modified=cve.last_modified.date(),
            status=cve.vuln_status,
            description=description,
            cvss=cvss,
            cwes=cwes,
            references=[r.url for r in cve.references[:5]],
            kev=kev,
        )


class BaseSearchResult(BaseModel):
    total_results: int
    results_per_page: int
    start_index: int
    next_start_index: Optional[int] = None
    pagination_hint: Optional[str] = None


class CveSearchResult(BaseSearchResult):
    vulnerabilities: list[CveSummary]

    @classmethod
    def from_response(cls, raw: NvdVulnerabilityData) -> CveSearchResult:
        next_index = raw.start_index + raw.results_per_page
        has_more = next_index < raw.total_results
        return cls(
            total_results=raw.total_results,
            results_per_page=raw.results_per_page,
            start_index=raw.start_index,
            vulnerabilities=[
                CveSummary.from_cve_item(item.cve) for item in raw.vulnerabilities
            ],
            next_start_index=next_index if has_more else None,
            pagination_hint=(
                f"{raw.total_results - next_index} more results available. "
                f"Call again with start_index={next_index} to get the next page."
            )
            if has_more
            else None,
        )


class ChangeDetail(BaseModel):
    type: str
    action: Optional[str] = None
    old: Optional[str] = None
    new: Optional[str] = None


class ChangeSummary(BaseModel):
    cve_id: str
    event: str
    source: str
    created: Optional[datetime] = None
    details: list[ChangeDetail]

    @classmethod
    def from_def_change(cls, def_change: DefChange) -> ChangeSummary:
        c = def_change.change
        return cls(
            cve_id=c.cve_id,
            event=c.event_name,
            source=c.source_identifier,
            created=c.created,
            details=[
                ChangeDetail(
                    type=d.type,
                    action=d.action,
                    old=d.old_value,
                    new=d.new_value,
                )
                for d in (c.details or [])
            ],
        )


class CveHistorySearchResult(BaseSearchResult):
    changes: list[ChangeSummary]

    @classmethod
    def from_response(cls, raw: NvdCveHistoryResponse) -> CveHistorySearchResult:
        next_index = raw.start_index + raw.results_per_page
        has_more = next_index < raw.total_results
        return cls(
            total_results=raw.total_results,
            results_per_page=raw.results_per_page,
            start_index=raw.start_index,
            next_start_index=next_index if has_more else None,
            pagination_hint=(
                f"{raw.total_results - next_index} more results available. "
                f"Call again with start_index={next_index} to get the next page."
            )
            if has_more
            else None,
            changes=[ChangeSummary.from_def_change(c) for c in (raw.cve_changes or [])],
        )
