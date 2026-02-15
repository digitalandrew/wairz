from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"), env_file_encoding="utf-8"
    )

    database_url: str = "postgresql+asyncpg://wairz:wairz@localhost:5432/wairz"
    redis_url: str = "redis://localhost:6379/0"
    anthropic_api_key: str = ""
    storage_root: str = "/data/firmware"
    max_upload_size_mb: int = 500
    max_tool_output_kb: int = 30
    max_tool_iterations: int = 25
    ghidra_path: str = "/opt/ghidra"
    ghidra_scripts_path: str = "/opt/ghidra_scripts"
    ghidra_timeout: int = 120
    nvd_api_key: str = ""
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
