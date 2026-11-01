"""HEIMDALL model loading and batch inference.

The implementation follows the supplied inference and ensemble notebooks.
Ensemble calibration bounds must be present in ensemble_meta.pkl; the helper
under backend/tools can add them using the matching benign validation flows.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from .settings import FEATURES


REQUIRED_ARTIFACTS = [
    "scaler_optionB.pkl",
    "gmm_optionB.pkl",
    "ae_expert_0.pt",
    "ae_expert_1.pt",
    "ae_expert_2.pt",
    "ae_expert_3.pt",
    "ae_expert_4.pt",
    "ae_expert_5.pt",
    "ocsvm_ensemble.pkl",
    "ensemble_meta.pkl",
]

CALIBRATION_KEYS = (
    "heimdall_val_min",
    "heimdall_val_max",
    "ocsvm_val_min",
    "ocsvm_val_max",
)


class ModelBundleError(RuntimeError):
    """Raised when the configured inference bundle is incomplete or invalid."""


class BehaviorAutoencoder(nn.Module):
    def __init__(self, input_dim: int = 6, bottleneck: int = 3):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.BatchNorm1d(16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.BatchNorm1d(8),
            nn.ReLU(),
            nn.Linear(8, bottleneck),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, values: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(values))

    def encode(self, values: torch.Tensor) -> torch.Tensor:
        return self.encoder(values)


def missing_artifacts(
    model_dir: str | Path, attribution_dir: str | Path | None = None
) -> list[str]:
    model_dir = Path(model_dir)
    attribution_dir = Path(attribution_dir) if attribution_dir else model_dir
    absent = [name for name in REQUIRED_ARTIFACTS if not (model_dir / name).is_file()]
    if not (model_dir / "botnet_profiles.pkl").is_file() and not (attribution_dir / "botnet_profiles.pkl").is_file():
        absent.append("botnet_profiles.pkl")
    return absent


class HEIMDALLInference:
    def __init__(
        self, model_dir: str | Path, attribution_dir: str | Path | None = None
    ):
        self.model_dir = Path(model_dir)
        self.attribution_dir = Path(attribution_dir) if attribution_dir else self.model_dir
        missing = missing_artifacts(self.model_dir, self.attribution_dir)
        if missing:
            raise ModelBundleError(
                "The trained model bundle is incomplete. Missing "
                + ", ".join(missing)
                + "."
            )

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        # Only load model files from a trusted, access-controlled source.
        self.scaler = joblib.load(self.model_dir / "scaler_optionB.pkl")
        self.gmm = joblib.load(self.model_dir / "gmm_optionB.pkl")
        self.ocsvm = joblib.load(self.model_dir / "ocsvm_ensemble.pkl")
        self.meta = joblib.load(self.model_dir / "ensemble_meta.pkl")
        profile_path = self.model_dir / "botnet_profiles.pkl"
        if not profile_path.is_file():
            profile_path = self.attribution_dir / "botnet_profiles.pkl"
        self.profiles = joblib.load(profile_path)

        if not isinstance(self.meta, dict):
            raise ModelBundleError("Ensemble metadata has an unsupported format.")
        if not all(key in self.meta for key in CALIBRATION_KEYS):
            raise ModelBundleError(
                "Ensemble metadata is missing score-calibration bounds. "
                "Run backend/tools/calibrate_ensemble.py with the matching benign "
                "validation-flow CSV, then restart the API."
            )
        if "threshold_balanced" not in self.meta:
            raise ModelBundleError("Ensemble metadata is missing its operating threshold.")

        self.weight_heimdall = float(self.meta.get("w_heimdall", 0.6))
        self.weight_ocsvm = float(self.meta.get("w_ocsvm", 0.4))
        weight_total = self.weight_heimdall + self.weight_ocsvm
        if weight_total <= 0:
            raise ModelBundleError("Ensemble weights must sum to a positive value.")
        self.weight_heimdall /= weight_total
        self.weight_ocsvm /= weight_total

        self.threshold = float(self.meta["threshold_balanced"])
        if not np.isfinite(self.threshold) or self.threshold <= 0:
            raise ModelBundleError("The configured operating threshold is invalid.")

        calibration = {key: float(self.meta[key]) for key in CALIBRATION_KEYS}
        for key, value in calibration.items():
            if not np.isfinite(value):
                raise ModelBundleError(f"Invalid calibration metadata: {key}.")
        if calibration["heimdall_val_max"] <= calibration["heimdall_val_min"]:
            raise ModelBundleError("HEIMDALL score-calibration range is empty.")
        if calibration["ocsvm_val_max"] <= calibration["ocsvm_val_min"]:
            raise ModelBundleError("OC-SVM score-calibration range is empty.")
        self.calibration = calibration

        scaler_features = int(getattr(self.scaler, "n_features_in_", 6))
        if scaler_features != 6:
            raise ModelBundleError(f"Expected a six-feature scaler, found {scaler_features} features.")
        n_experts = int(self.gmm.n_components)
        if n_experts != 6:
            raise ModelBundleError(
                f"Expected six trained experts, but the GMM specifies {n_experts}."
            )

        self.experts: list[BehaviorAutoencoder] = []
        for index in range(n_experts):
            expert = BehaviorAutoencoder().to(self.device)
            state = torch.load(
                self.model_dir / f"ae_expert_{index}.pt",
                map_location=self.device,
                weights_only=True,
            )
            expert.load_state_dict(state)
            expert.eval()
            self.experts.append(expert)

        if not isinstance(self.profiles, dict) or not self.profiles:
            raise ModelBundleError("Attribution profiles are empty or unsupported.")

        self.profile_vectors: dict[str, np.ndarray] = {}
        for name, vector in self.profiles.items():
            array = np.asarray(vector, dtype=np.float32).reshape(-1)
            if array.size != 3 or not np.isfinite(array).all():
                raise ModelBundleError(f"Invalid attribution profile: {name}.")
            self.profile_vectors[str(name)] = array

    @staticmethod
    def _normalize_scores(values: np.ndarray, lower: float, upper: float) -> np.ndarray:
        return np.clip((values - lower) / (upper - lower + 1e-10), 0.0, 1.0)

    @staticmethod
    def _cosine_similarity(left: np.ndarray, right: np.ndarray) -> float:
        denominator = float(np.linalg.norm(left) * np.linalg.norm(right))
        if denominator <= 1e-12:
            return 0.0
        return float(np.dot(left, right) / denominator)

    def _risk_level(self, score: float) -> str:
        if score <= self.threshold:
            return "NORMAL"
        if score <= 2 * self.threshold:
            return "LOW"
        if score <= 5 * self.threshold:
            return "MEDIUM"
        return "HIGH"

    @staticmethod
    def _recommended_actions(risk: str) -> list[str]:
        return {
            "NORMAL": ["No immediate action indicated"],
            "LOW": ["Review the flow in context", "Increase monitoring for the source device"],
            "MEDIUM": ["Escalate for analyst review", "Inspect related connections and device activity"],
            "HIGH": ["Prioritise incident triage", "Review containment options under local policy"],
        }[risk]

    def predict_batch(self, feature_rows: pd.DataFrame) -> list[dict[str, Any]]:
        if feature_rows.empty:
            return []
        raw = feature_rows[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)
        scaled = np.clip(self.scaler.transform(raw.values.astype(np.float32)), 0.0, 1.0)
        probabilities = self.gmm.predict_proba(scaled)
        tensor = torch.as_tensor(scaled, dtype=torch.float32, device=self.device)
        per_flow_heimdall = np.zeros(len(scaled), dtype=np.float32)
        embeddings = np.zeros((len(scaled), 3), dtype=np.float32)
        criterion = nn.MSELoss(reduction="none")
        dominant_expert = probabilities.argmax(axis=1)

        with torch.no_grad():
            for index, expert in enumerate(self.experts):
                reconstructed = expert(tensor)
                errors = criterion(reconstructed, tensor).mean(dim=1)
                per_flow_heimdall += probabilities[:, index] * errors.cpu().numpy()
                mask = dominant_expert == index
                if np.any(mask):
                    embeddings[mask] = expert.encode(tensor[mask]).cpu().numpy()

        per_flow_ocsvm = -np.asarray(self.ocsvm.decision_function(scaled)).reshape(-1)
        heimdall_normalized = self._normalize_scores(
            per_flow_heimdall,
            self.calibration["heimdall_val_min"],
            self.calibration["heimdall_val_max"],
        )
        ocsvm_normalized = self._normalize_scores(
            per_flow_ocsvm,
            self.calibration["ocsvm_val_min"],
            self.calibration["ocsvm_val_max"],
        )
        fused = (
            self.weight_heimdall * heimdall_normalized
            + self.weight_ocsvm * ocsvm_normalized
        )

        output: list[dict[str, Any]] = []
        for index, row in enumerate(feature_rows.to_dict(orient="records")):
            best_name = "Unattributed"
            best_similarity = -1.0
            for profile_name, profile in self.profile_vectors.items():
                similarity = self._cosine_similarity(embeddings[index], profile)
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_name = profile_name

            score = float(fused[index])
            risk = self._risk_level(score)
            output.append(
                {
                    "flow_id": int(row["flow_id"]),
                    "protocol": row["protocol"],
                    "source_ip": row["source_ip"],
                    "destination_ip": row["destination_ip"],
                    "source_port": int(row["source_port"]),
                    "destination_port": int(row["destination_port"]),
                    "packet_count": int(row["packet_count"]),
                    "total_bytes": int(row["total_bytes"]),
                    "flow_duration": float(row["flow_duration"]),
                    "anomaly_score": score,
                    "risk_level": risk,
                    "attribution": best_name,
                    "attribution_similarity": float(best_similarity),
                    "is_anomalous": risk != "NORMAL",
                    "actions": self._recommended_actions(risk),
                }
            )
        return output
