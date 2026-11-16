# PHAROS CDR

**PHAROS** (Proactive Hazard Analysis, Reconstruction & Obfuscation Sanitization) is a dual-engine document security platform that combines **Machine Learning Threat Detection** with deterministic **Content Disarm and Reconstruction (CDR)**.

Instead of relying solely on signature detection, PHAROS decomposes incoming document archives (`.docx`, `.docm`, `.doc`), inspects internal structures (macros, embedded payloads, OLE streams, external relationships), scores file risk via a trained ML classifier, disarms malicious artifacts, and reconstructs a clean, functional document.

---

## Architecture & How It Works

```
Uploaded Document (.docx / .docm / .doc)
         │
         ▼
[ Ingestion & Signature Validation ]
         │
         ▼
[ Feature Extractor & ML Classifier ] ──► Threat Risk Score & Indicators
         │
         ▼
[ Decision Engine (Pass / Sanitize / Reject) ]
         │
         ├─► Clean Document: Preserved unmodified
         ├─► Malicious / Risky: Disarmed (strips VBA macros, exploits, active content)
         └─► Reconstructed: Verified safe document generated
         │
         ▼
[ LLM Threat Intelligence Brief ] ──► Plain-language analyst summary
         │
         ▼
[ Web Dashboard & Audit Log ] ──► Report, Sanitized Download, Scan History
```

### Key Capabilities
- **Deterministic Disarmament**: Extracts XML structures and media, strips active payloads, drops hostile relationships, and rebuilds OOXML packages safely.
- **ML Detection**: Multi-feature structural analysis to identify zero-day weaponization, macro abuse, and evasion patterns.
- **AI Executive Brief**: Translates technical risk indicators into human-readable executive summaries via Google Gemini API or local Ollama.
- **Web Portal**: Full multi-user interface with user registration, session management, scan history with CSV export, search filters, and profile management.

---

## Local Setup

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Git

### 2. Clone and Setup Environment
```bash
git clone <repository-url>
cd PHAROS

python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Environment Configuration
Create a `.env` file from the example:
```bash
cp .env.example .env
```

Generate a secure Flask secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Configure your `.env` values:
```env
FLASK_ENV=development
PHAROS_SECRET_KEY=your-generated-secret-key

# Optional: Set Gemini API key for cloud LLM threat summaries
# GEMINI_API_KEY=your-api-key-here

# Optional: Set Ollama host if using local LLM
OLLAMA_MODEL=pharos-llm
OLLAMA_HOST=http://localhost:11434
```

### 4. Run Locally

**Option A — Web Application (Flask):**
```bash
python -m web.app
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

**Option B — REST API (FastAPI):**
```bash
uvicorn src.api.app:app --reload --port 8000
```
API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Cloud Deployment

### 1. Deploying to Render (Recommended)

Render is ideal for persistent Python backend services and background file processing.

1. **Push your code to GitHub** (ensure `.env` and `user_database/` are ignored).
2. Go to [Render Dashboard](https://dashboard.render.com/) → **New +** → **Web Service**.
3. Connect your GitHub repository.
4. Set the following build and start configurations:
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn "web.app:app" --bind 0.0.0.0:$PORT --workers 2 --threads 2 --timeout 120`
5. **Add Environment Variables** in Render's dashboard:
   - `PHAROS_SECRET_KEY`: Long random string.
   - `FLASK_ENV`: `production`
   - `GEMINI_API_KEY`: Your Google AI Studio API key (cloud LLM summary).
   - `PYTHON_VERSION`: `3.12`
6. *(Optional - Data Persistence)*: Free instances have ephemeral storage. To retain user database and sanitized files across redeployments, attach a **Persistent Disk** mounted at `/data` and set `PHAROS_DB_PATH=/data/pharos_users.db`.

> **Note**: A preconfigured `render.yaml` and `Procfile` are already included in the root directory for automated deployment.

---

### 2. Deploying to Vercel

> **Important**: Vercel is built for **stateless, serverless functions** with a 10–60 second execution limit and read-only filesystems (only `/tmp` is writable). Because PHAROS performs heavy document unpacking and file reconstruction, consider the following requirements when deploying to Vercel:

1. **Install Vercel CLI**:
   ```bash
   npm install -g vercel
   ```
2. **Configuration (`vercel.json`)**:
   Create a `vercel.json` file in the root directory:
   ```json
   {
     "builds": [
       {
         "src": "web/app.py",
         "use": "@vercel/python"
       }
     ],
     "routes": [
       {
         "src": "/(.*)",
         "dest": "web/app.py"
       }
     ]
   }
   ```
3. **Storage Considerations**:
   - SQLite files stored inside the repository cannot be written to in Vercel production.
   - You must either configure a cloud database (e.g., PostgreSQL / Supabase / Turso) or configure the SQLite database path to write inside `/tmp`.
4. **Deploy**:
   ```bash
   vercel
   ```
   Add `PHAROS_SECRET_KEY` and `GEMINI_API_KEY` in the Vercel Project Settings under **Environment Variables**.

---

## Running Tests

Run the test suite to ensure parser, sanitizer, and pipeline integrity:
```bash
pytest -v
```

---

## Security & Best Practices

- **Sandboxing**: When analyzing untrusted live malware samples, run the service in an isolated container or virtual machine.
- **Secret Management**: Never commit actual `.env` files, API keys, or production databases to public Git repositories.
- **Safe Handling**: Sanitized outputs are disarmed, but original inputs remain potentially dangerous—never open raw malicious samples in standard desktop software.
