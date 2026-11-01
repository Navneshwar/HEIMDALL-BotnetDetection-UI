from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
MODEL_DIR = BACKEND_DIR / "models"
ATTRIBUTION_DIR = BACKEND_DIR / "attribution"

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB
MAX_PACKETS = 1_000_000
MAX_FLOWS = 100_000
FLOW_IDLE_TIMEOUT_SECONDS = 60.0

FEATURES = [
    "flow_duration",
    "packet_count",
    "total_bytes",
    "mean_packet_size",
    "mean_inter_arrival_time",
    "bytes_per_second",
]

RISK_LEVELS = ("NORMAL", "LOW", "MEDIUM", "HIGH")
