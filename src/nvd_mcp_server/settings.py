from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
    )

    retry_max_duration: int = Field(
        default=120, description="Total time budget (seconds) for a request and all its retries."
    )
    total_timeout: float = Field(
        default=60.0, description="Per-request HTTP timeout in seconds."
    )
    nvd_api_key: str = Field(
        description="API key for National Vulnerability Database access"
    )
    nvd_cve_url: HttpUrl = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="Base URL for NVD CVE API endpoints",
    )
    nvd_cve_history_url: HttpUrl = Field(
        default="https://services.nvd.nist.gov/rest/json/cvehistory/2.0",
        description="Base URL for NVD CVE history API endpoints",
    )
