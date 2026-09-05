# Pharos CDR

**Pharos CDR** is a malware detection and Content Disarm and Reconstruction (CDR) project designed to analyze potentially malicious documents, extract security-relevant features, classify files using machine learning, and sanitize suspicious documents.

The project is intended for controlled security research and production-oriented document security applications.

---

# Getting Started

## 1. Clone the repository

Clone the project and move into the project directory:

```bash
git clone <repository-url>
cd pharos-cdr
```

---

## 2. Create a virtual environment

Create a Python virtual environment:

```bash
python -m venv .venv
```

---

## 3. Activate the virtual environment

### Windows

```powershell
.venv\Scripts\activate
```

### Linux/macOS

```bash
source .venv/bin/activate
```

After activation, your terminal should show something similar to:

```text
(.venv)
```

---

## 4. Install dependencies

Upgrade `pip`:

```bash
python -m pip install --upgrade pip
```

Install the project dependencies:

```bash
pip install -r requirements.txt
```

---

# Machine Learning

The machine-learning component is used to classify documents based on extracted security and structural features.

The project maintains a comprehensive feature set covering document structure, Office components, VBA/macros, scripts, execution capabilities, filesystem and registry activity, network capabilities, persistence, obfuscation, evasion, payload characteristics, and other security-relevant properties.

Model training and experimentation can be performed using **Google Colab**.

When using Colab, install the project dependencies in the notebook environment as required:

```python
!pip install -r requirements.txt
```

Trained models and their associated metadata should be stored separately from raw datasets and sensitive test files.

---

# Running the Project

## Run Tests

Run the complete test suite using:

```bash
pytest
```

For more detailed output:

```bash
pytest -v
```

---

## Start the API

Start the FastAPI development server with:

```bash
uvicorn src.api.app:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

For production deployments, use an appropriate production ASGI configuration rather than relying on the development `--reload` option.

---

# API Documentation

Once the API is running, open the interactive Swagger documentation:

```text
http://127.0.0.1:8000/docs
```

Alternative ReDoc documentation:

```text
http://127.0.0.1:8000/redoc
```

---

# Environment Variables

If environment-specific configuration is required, copy:

```text
.env.example
```

to:

```text
.env
```

Example:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Do **not** commit `.env` to version control if it contains secrets, credentials, API keys, or environment-specific configuration.

---

# Useful Commands

### Create environment

```bash
python -m venv .venv
```

### Activate — Windows

```powershell
.venv\Scripts\activate
```

### Activate — Linux/macOS

```bash
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run tests

```bash
pytest
```

### Run tests with verbose output

```bash
pytest -v
```

### Start API

```bash
uvicorn src.api.app:app --reload
```

### Open API documentation

```text
http://127.0.0.1:8000/docs
```

---

# Security Notice

This project is intended for controlled malware-analysis and document-sanitization research.

Treat unknown or malicious files as potentially dangerous. Do not open suspicious documents using normal desktop applications.

Testing involving potentially malicious documents should preferably be performed in an isolated environment such as a dedicated virtual machine or sandbox.

Do not use real confidential documents, personal data, credentials, or other sensitive files as test data.

The CDR process should preserve the original input and produce a separate sanitized output. Original files should not be modified or overwritten during processing.