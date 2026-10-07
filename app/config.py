from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path


def _decode_aes_key(value: str) -> bytes:
    cleaned = value.strip()
    if len(cleaned) == 64:
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            raw = b""
        if len(raw) == 32:
            return raw
    padded = cleaned + ("=" * (-len(cleaned) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise ValueError("AES_KEY deve ter 32 bytes em hex (64 caracteres) ou base64 url-safe") from exc
    if len(raw) != 32:
        raise ValueError("AES_KEY deve ter 32 bytes")
    return raw


def load_secret_file(path: Path, nbytes: int | None = None) -> bytes:
    if path.exists():
        data = path.read_bytes()
        if nbytes is None or len(data) == nbytes:
            return data
    data = os.urandom(nbytes or 32)
    path.write_bytes(data)
    return data


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    jwt_secret: str
    aes_key: bytes
    bedrock_mode: str = "auto"
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "amazon.nova-lite-v1:0"
    usage_limit_hours: float = 24.0

    @property
    def db_path(self) -> Path:
        return self.data_dir / "operator.db"

    @staticmethod
    def from_env() -> "Settings":
        data_dir = Path(os.environ.get("DATA_DIR", "data"))
        data_dir.mkdir(parents=True, exist_ok=True)

        jwt_env = os.environ.get("JWT_SECRET", "").strip()
        if jwt_env:
            jwt_secret = jwt_env
        else:
            jwt_secret = load_secret_file(data_dir / "jwt.secret").hex()

        aes_env = os.environ.get("AES_KEY", "").strip()
        aes_key = _decode_aes_key(aes_env) if aes_env else load_secret_file(data_dir / "aes.key", 32)

        mode = os.environ.get("BEDROCK_MODE", "auto").strip().lower() or "auto"
        if mode not in {"auto", "required", "off"}:
            raise ValueError("BEDROCK_MODE deve ser auto, required ou off")

        return Settings(
            data_dir=data_dir,
            jwt_secret=jwt_secret,
            aes_key=aes_key,
            bedrock_mode=mode,
            aws_region=os.environ.get("AWS_REGION", "us-east-1").strip() or "us-east-1",
            bedrock_model_id=os.environ.get("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0").strip()
            or "amazon.nova-lite-v1:0",
            usage_limit_hours=float(os.environ.get("USAGE_LIMIT_HOURS", "24")),
        )
