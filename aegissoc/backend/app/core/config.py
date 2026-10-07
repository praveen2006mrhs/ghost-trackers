import os

class Settings:
    PROJECT_NAME: str = "Ghost Trackers - AegisSOC"
    PROJECT_DESCRIPTION: str = "Defensive Cybersecurity Operations & Threat Intelligence Suite"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./aegissoc.db")
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "*"
    ]
    SANDBOX_MODE: bool = True
    MAX_UPLOAD_SIZE_MB: int = 15

settings = Settings()
