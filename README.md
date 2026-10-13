# IntentLock

> Cryptographic intent verification prototype preventing hijacked AI agents from executing unapproved actions.

**Notice**: IntentLock is an educational hackathon prototype designed to demonstrate the concept of cryptographically bound human approval tokens. The AI agent in the demo is a deterministic simulation of a hijacked agent, not a live production model. This project is a prototype and should not be considered hardened or unhackable for production environments.

---

## Architecture Overview

1. **Approval Dashboard**: Human reviews and approves specific pending agent proposals.
2. **Token Issuer**: Generates single-use Ed25519-signed authorization tokens bound strictly to the approved parameters.
3. **Store Verifier**: Validates digital signatures, enforces exact parameters (item, payee, amount, store), and atomically consumes one-time nonces.

---

## Getting Started

### 1. Prerequisites
- Python 3.11+
- Git

### 2. Setup Virtual Environment
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Or Windows Command Prompt
# .venv\Scripts\activate.bat

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
# Copy example configuration (edit if needed)
copy .env.example .env
```

### 4. Run the Development Server
```bash
uvicorn app.main:app --reload
```

Visit the health check at: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### 5. Run Tests
```bash
pytest -q
```
