# HEIMDALL — Network Capture Analysis

HEIMDALL is a local web application for reviewing packet captures and identifying network flows that may warrant security investigation. Upload a PCAP or PCAPNG file, run the configured detection model, and review a clear capture-level assessment alongside flow-level findings.

This repository contains the application interface and inference service only. It is intentionally written as a product and deployment guide; it does not document the underlying research, model design, training process, evaluation datasets, internal thresholds, or experimental results.

## What the application provides

- **Packet-capture upload:** accepts PCAP, PCAPNG, and CAP files through a browser interface.
- **Flow inspection:** groups supported network traffic into bidirectional conversations and derives the metadata needed for analysis.
- **Capture assessment:** presents whether suspicious activity was detected by the configured model.
- **Investigation view:** shows risk distribution, profile summaries, and searchable per-flow results.
- **Result export:** downloads the flow-level findings as a CSV file.
- **Local processing:** the development setup sends uploads to the local Python service. Temporary capture files are removed after processing.

The interface is designed for analyst triage. A detection result is not, by itself, proof of compromise; an absence of alerts is not a guarantee that a capture is benign.

## Technology

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI |
| Capture parsing | Scapy |
| Inference runtime | PyTorch, scikit-learn, NumPy, pandas |

## Project layout

```text
heimdall_webapp/
├── backend/
│   ├── app/
│   │   ├── feature_extraction.py
│   │   ├── inference.py
│   │   ├── main.py
│   │   └── settings.py
│   ├── models/              
│   ├── attribution/         
│   ├── tools/               
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── index.html
│   ├── package.json
│   └── vite.config.ts
├── .gitignore
└── README.md
```

Do not copy notebooks, raw captures, training datasets, research reports, credentials, or unrelated project files into this application directory. The `backend/models/` and `backend/attribution/` folders are reserved for the approved inference bundle and its required reference profiles.

## Requirements

- Python 3.10 or newer
- Node.js 20 or newer and npm
- 4 GB RAM recommended for local testing; larger captures may require more
- The approved HEIMDALL inference bundle, obtained through the project's private model distribution process

A trained model bundle is not included in this repository. This keeps model files separate from the application source and avoids accidentally publishing restricted project assets. Until the approved bundle is installed, the website will load normally but the API will report that inference is unavailable and will not fabricate results.

## Run locally

Open two terminal windows from the project root.

### 1. Start the Python backend

```bash
cd backend
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

```powershell
.venv\Scripts\Activate.ps1
```

**macOS / Linux**

```bash
source .venv/bin/activate
```

Install dependencies and start the API:

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The API health endpoint is available at `http://127.0.0.1:8000/api/health` and the interactive API reference is at `http://127.0.0.1:8000/docs`.

### 2. Start the React frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local address printed by Vite, normally `http://localhost:5173`.

The Vite development server forwards `/api` requests to the Python backend on port `8000`.

## Configure the private model bundle

The inference service expects a compatible, versioned model bundle in `backend/models/` and `backend/attribution/`. Obtain the bundle from the project's authorised private source and follow the internal release instructions for the matching model version. Do not rename, edit, or mix files from different model releases.

After installing or updating the bundle, restart the Python backend. The header and system-status panel will indicate when inference is ready. If the health endpoint reports that the model is unavailable, check the backend console for the specific configuration issue.

**Important:** model files serialised with Python pickle/joblib must only be loaded from a trusted source. A malicious or altered model file can execute code when deserialised.

## Use the application

1. Open the frontend in a browser.
2. Confirm that the system status shows the inference service as ready.
3. Select or drag a `.pcap`, `.pcapng`, or `.cap` file into the upload area.
4. Select **Analyse capture**.
5. Review the capture assessment, risk distribution, attribution summary, and flow-level table.
6. Use the filters or search field to narrow the flow list. Select **Export CSV** to save the complete flow results.

The current upload limit is 100 MB. The parser analyses IPv4 and IPv6 TCP/UDP traffic. Other packet types are excluded from flow inference and counted in the processing summary.

## API overview

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Check API and model availability |
| `POST` | `/api/analyze` | Upload and analyse a packet capture |

The analysis endpoint expects a multipart form upload with the field name `file`.

## Privacy and operational notes

- The default development configuration is intended for local use.
- Uploaded captures are written to a temporary file for parsing and deleted after the request finishes.
- The application does not retain a capture archive or upload history.
- Restrict access to the host and model directory. Do not expose the development server directly to the public internet.
- Before deploying to a shared environment, configure production-grade authentication, HTTPS, upload controls, logging, and access restrictions.
- Review all suggested response actions under your organisation's security policies. The application reports findings; it does not automatically block, quarantine, or modify network devices.

## Troubleshooting

**The page says “Model not configured”.**  
The Python API is reachable, but the approved inference bundle is not available or did not pass validation. Check the backend console and the private model-release instructions.

**The page says “Backend unavailable”.**  
Confirm that the API is running on `127.0.0.1:8000`, then refresh the service status in the browser.

**The capture is rejected.**  
Confirm that the file is a valid PCAP/PCAPNG capture, is not empty, and is smaller than 100 MB. Captures without supported IPv4/IPv6 TCP/UDP packets cannot be analysed by this version.

**The results differ across environments.**  
Use the matching approved model release and its deployment configuration. Do not combine files from different releases or use untrusted serialised models.

## Disclaimer

HEIMDALL is a decision-support tool for network security triage. Its output should be interpreted alongside other security telemetry, packet-capture context, and analyst review. It is not a substitute for a complete incident-response process.
