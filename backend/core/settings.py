from __future__ import annotations
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PWNMAP_",
        env_file=".env",
        extra="ignore",
    )

    # Server
    server_bind: str            # PWNMAP_SERVER_BIND
    server_port: int            # PWNMAP_SERVER_PORT

    # Auth
    auth_token: str | None = None  # PWNMAP_AUTH_TOKEN

    # WPA-SEC
    wpasec_url: str             # PWNMAP_WPASEC_URL
    wpasec_key: str             # PWNMAP_WPASEC_KEY

    # Paths
    data_dir: Path              # PWNMAP_DATA_DIR
    db_path: Path               # PWNMAP_DB_PATH
    vendor_oui_csv: Path        # PWNMAP_VENDOR_OUI_CSV

    def model_post_init(self, __context) -> None:
        # Normalizza percorsi in assoluto e crea le cartelle se mancano
        data_dir = Path(self.data_dir).expanduser().resolve()
        db_path = Path(self.db_path)
        vendor_csv = Path(self.vendor_oui_csv)

        if not db_path.is_absolute():
            db_path = (Path.cwd() / db_path).resolve()
        if not vendor_csv.is_absolute():
            vendor_csv = (Path.cwd() / vendor_csv).resolve()

        data_dir.mkdir(parents=True, exist_ok=True)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        vendor_csv.parent.mkdir(parents=True, exist_ok=True)

        object.__setattr__(self, "data_dir", data_dir)
        object.__setattr__(self, "db_path", db_path)
        object.__setattr__(self, "vendor_oui_csv", vendor_csv)

settings = Settings()
