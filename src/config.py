from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    risk_strategy: str = "linear"
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 2
    log_level: str = "info"

    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()