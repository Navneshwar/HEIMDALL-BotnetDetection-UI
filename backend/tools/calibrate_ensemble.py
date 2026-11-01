"""Add the score-normalization bounds required by the deployed ensemble.

Use the same benign validation-flow sample used when the ensemble threshold
was selected. The CSV is read for this operation only and is not copied into
or retained by the application. Only four scalar calibration bounds are
written to ensemble_meta.pkl.

Example:
  python backend/tools/calibrate_ensemble.py --validation-csv /secure/path/benign_validation_flows.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.inference import BehaviorAutoencoder  # noqa: E402
from app.settings import FEATURES, MODEL_DIR  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation-csv", required=True, type=Path)
    args = parser.parse_args()

    if not args.validation_csv.is_file():
        raise SystemExit(f"Validation CSV not found: {args.validation_csv}")

    required = [
        "scaler_optionB.pkl", "gmm_optionB.pkl", "ocsvm_ensemble.pkl",
        "ensemble_meta.pkl", *[f"ae_expert_{i}.pt" for i in range(6)],
    ]
    absent = [name for name in required if not (MODEL_DIR / name).is_file()]
    if absent:
        raise SystemExit("Missing model assets: " + ", ".join(absent))

    frame = pd.read_csv(args.validation_csv, low_memory=False)
    if "label" in frame.columns:
        frame = frame[frame["label"].astype(str).str.strip().str.lower().isin({"benign", "normal", "normal traffic"})]
    missing_columns = [name for name in FEATURES if name not in frame.columns]
    if missing_columns:
        raise SystemExit("Validation CSV is missing columns: " + ", ".join(missing_columns))
    frame = frame[FEATURES].replace([np.inf, -np.inf], np.nan).dropna()
    if len(frame) < 100:
        raise SystemExit("Provide at least 100 valid benign validation flows.")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    scaler = joblib.load(MODEL_DIR / "scaler_optionB.pkl")
    gmm = joblib.load(MODEL_DIR / "gmm_optionB.pkl")
    ocsvm = joblib.load(MODEL_DIR / "ocsvm_ensemble.pkl")
    meta = joblib.load(MODEL_DIR / "ensemble_meta.pkl")

    X = np.clip(scaler.transform(frame.values.astype(np.float32)), 0.0, 1.0)
    probabilities = gmm.predict_proba(X)
    tensor = torch.as_tensor(X, dtype=torch.float32, device=device)
    criterion = nn.MSELoss(reduction="none")
    heimdall_scores = np.zeros(len(X), dtype=np.float32)

    experts = []
    for index in range(int(gmm.n_components)):
        expert = BehaviorAutoencoder().to(device)
        state = torch.load(
            MODEL_DIR / f"ae_expert_{index}.pt",
            map_location=device,
            weights_only=True,
        )
        expert.load_state_dict(state)
        expert.eval()
        experts.append(expert)

    with torch.no_grad():
        for index, expert in enumerate(experts):
            errors = criterion(expert(tensor), tensor).mean(dim=1).cpu().numpy()
            heimdall_scores += probabilities[:, index] * errors

    ocsvm_scores = -np.asarray(ocsvm.decision_function(X)).reshape(-1)
    heimdall_min, heimdall_max = float(np.min(heimdall_scores)), float(np.max(heimdall_scores))
    ocsvm_min, ocsvm_max = float(np.min(ocsvm_scores)), float(np.max(ocsvm_scores))
    heimdall_norm = np.clip((heimdall_scores - heimdall_min) / (heimdall_max - heimdall_min + 1e-10), 0.0, 1.0)
    ocsvm_norm = np.clip((ocsvm_scores - ocsvm_min) / (ocsvm_max - ocsvm_min + 1e-10), 0.0, 1.0)
    weight_h = float(meta.get("w_heimdall", 0.6))
    weight_s = float(meta.get("w_ocsvm", 0.4))
    weight_sum = weight_h + weight_s
    if weight_sum <= 0:
        raise SystemExit("Ensemble weights must sum to a positive value.")
    ensemble_validation = (weight_h / weight_sum) * heimdall_norm + (weight_s / weight_sum) * ocsvm_norm
    meta.update(
        {
            "heimdall_val_min": heimdall_min,
            "heimdall_val_max": heimdall_max,
            "ocsvm_val_min": ocsvm_min,
            "ocsvm_val_max": ocsvm_max,
            "threshold_balanced": float(np.percentile(ensemble_validation, 85)),
            "threshold_calibration_percentile": 85,
        }
    )
    joblib.dump(meta, MODEL_DIR / "ensemble_meta.pkl")
    print("Ensemble score-calibration bounds and the benign 85th-percentile threshold were saved.")
    print("Validation data was not copied into the application.")


if __name__ == "__main__":
    main()
