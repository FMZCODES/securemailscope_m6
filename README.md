# SecureMailScope — M6 Starter

This is the first M6 foundation for SecureMailScope.

## Included

- FastAPI application
- PCAP upload endpoint
- Temporary in-memory analysis storage
- Mock analysis result
- JSON result endpoint
- HTML report endpoint
- Health-check endpoint

## Setup on Windows

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open the API documentation:

http://127.0.0.1:8000/docs

## Endpoints

- `GET /`
- `GET /health`
- `POST /upload-pcap`
- `GET /results/{analysis_id}`
- `GET /report/{analysis_id}/json`
- `GET /report/{analysis_id}/html`

## Important

The current analysis result is mock data. Later, M2–M5 outputs will replace the mock data, and MongoDB will replace the temporary in-memory dictionary.
