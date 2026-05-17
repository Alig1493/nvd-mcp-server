from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING, Optional

from pydantic import BaseModel

if TYPE_CHECKING:
    from .core import CveItem


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
        description = next(
            (d.value for d in cve.descriptions if d.lang == "en"), ""
        )

        cvss: CvssSummary | None = None
        m = cve.metrics
        if m:
            if m.cvss_metric_v40:
                p = next(
                    (x for x in m.cvss_metric_v40 if x.type == "Primary"),
                    m.cvss_metric_v40[0],
                )
                cvss = CvssSummary(
                    version="4.0",
                    score=p.cvss_data.base_score,
                    severity=p.cvss_data.base_severity,
                    vector=p.cvss_data.vector_string,
                )
            elif m.cvss_metric_v31:
                p = next(
                    (x for x in m.cvss_metric_v31 if x.type == "Primary"),
                    m.cvss_metric_v31[0],
                )
                cvss = CvssSummary(
                    version="3.1",
                    score=p.cvss_data.base_score,
                    severity=p.cvss_data.base_severity,
                    vector=p.cvss_data.vector_string,
                )
            elif m.cvss_metric_v30:
                p = next(
                    (x for x in m.cvss_metric_v30 if x.type == "Primary"),
                    m.cvss_metric_v30[0],
                )
                cvss = CvssSummary(
                    version="3.0",
                    score=p.cvss_data.base_score,
                    severity=p.cvss_data.base_severity,
                    vector=p.cvss_data.vector_string,
                )
            elif m.cvss_metric_v2:
                p = next(
                    (x for x in m.cvss_metric_v2 if x.type == "Primary"),
                    m.cvss_metric_v2[0],
                )
                cvss = CvssSummary(
                    version="2.0",
                    score=p.cvss_data.base_score,
                    severity=p.base_severity or "",
                    vector=p.cvss_data.vector_string,
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


class CveSearchResult(BaseModel):
    total_results: int
    results_per_page: int
    start_index: int
    vulnerabilities: list[CveSummary]
    next_start_index: Optional[int] = None
    pagination_hint: Optional[str] = None
