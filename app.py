from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File, Form
from pydantic import BaseModel
from contextlib import asynccontextmanager
import httpx
import os
import datetime
import logging
import json
import re
import aiofiles
import asyncpg
import hashlib
import imagehash
from PIL import Image
import io

# ---------------------------------------------------------
# Database Connection Pool Lifespan
# ---------------------------------------------------------
db_pool = None
DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel_admin:secure_local_password@sentinel-db:5432/vic_hashes")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    # Connect to PostgreSQL on startup
    db_pool = await asyncpg.create_pool(DB_URL)
    yield
    # Close pool on shutdown
    await db_pool.close()

app = FastAPI(title="Sentinel Edge Node UI", lifespan=lifespan)

# Directory & Template setups
EXPORT_DIR = "./knowledge_graph_exports"
os.makedirs(EXPORT_DIR, exist_ok=True)
templates = Jinja2Templates(directory="templates")

LLAMA_API_URL = os.getenv("LLAMA_API_URL", "http://inference-engine:8080/completion")

# Models
class QueryRequest(BaseModel):
    prompt: str

class ExportRequest(BaseModel):
    entity_name: str
    aliases: list[str]
    connections: list[str]
    summary: str
    source_file: str

class HashVerifyRequest(BaseModel):
    hash_type: str
    hash_value: str

# ---------------------------------------------------------
# NIEM CORE SCHEMAS & PROMPTS
# ---------------------------------------------------------
NIEM_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "@context": {
            "type": "object",
            "properties": {
                "nc": {"type": "string", "enum": ["http://release.niem.gov/niem/niem-core/6.0/#"]}
            },
            "required": ["nc"],
            "additionalProperties": False
        },
        "nc:Person": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "nc:PersonFullName": {"type": "string"},
                    "nc:PersonBirthDate": {
                        "type": "object",
                        "properties": {
                            "nc:Date": {"type": "string"}
                        },
                        "required": ["nc:Date"],
                        "additionalProperties": False
                    },
                    "nc:PersonPhoneNumber": {"type": "string"}
                },
                "required": ["nc:PersonFullName"],
                "additionalProperties": False
            }
        },
        "nc:Vehicle": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "nc:VehicleMakeCode": {"type": "string"},
                    "nc:VehicleModelCode": {"type": "string"},
                    "nc:VehicleLicensePlateIdentification": {"type": "string"}
                },
                "required": ["nc:VehicleLicensePlateIdentification"],
                "additionalProperties": False
            }
        }
    },
    "required": ["@context", "nc:Person", "nc:Vehicle"],
    "additionalProperties": False
}

SYSTEM_PROMPT = """You are an automated law enforcement intelligence extractor running in a secure, zero-knowledge environment.
Your objective is to read raw, unstructured case files, chat logs, and investigator notes, and extract critical entities.

Rules for Extraction:
1. ONLY extract information explicitly present in the provided text. Do not hallucinate, infer, or guess missing information.
2. If an entity type is not found in the text, return an empty array for that field.
3. Output the extracted data strictly in the requested JSON structure using the NIEM (National Information Exchange Model) Core 'nc:' namespace.
4. Provide absolutely no conversational filler or markdown formatting. Just output the JSON object.
"""

# ---------------------------------------------------------
# Security & Auditing (Kept from previous version)
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[AUDIT] %(asctime)s - %(message)s",
    handlers=[logging.FileHandler("cjis_audit.log")]
)
audit_logger = logging.getLogger("CJIS_Audit")

async def verify_cjis_attributes(request: Request):
    user_id = request.headers.get("X-GFIPM-User-ID", "UNKNOWN_USER")
    is_icac_active = request.headers.get("X-GFIPM-ICAC-Active", "False")
    mfa_verified = request.headers.get("X-MFA-Verified", "False")

    if mfa_verified != "True":
        audit_logger.warning(f"Event: Authentication_Failed | UserID: {user_id} | Reason: Missing MFA token")
        raise HTTPException(status_code=401, detail="Hardware MFA token required.")
    if is_icac_active != "True":
        audit_logger.warning(f"Event: Access_Denied | UserID: {user_id} | Reason: Lacks ICAC attribute")
        raise HTTPException(status_code=403, detail="ABAC Violation: Required attributes not met.")
    return user_id

@app.middleware("http")
async def zero_knowledge_audit_middleware(request: Request, call_next):
    endpoint = request.url.path
    user_id = request.headers.get("X-GFIPM-User-ID", "UNAUTHENTICATED")
    response = await call_next(request)
    if not endpoint.startswith(("/static", "/favicon")):
        audit_logger.info(f"Event: API_Transaction | UserID: {user_id} | Endpoint: {endpoint} | Status: {response.status_code}")
    return response

# ---------------------------------------------------------
# Core API Routes
# ---------------------------------------------------------
@app.get("/")
async def serve_ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/query", dependencies=[Depends(verify_cjis_attributes)])
async def query_model(request: QueryRequest):
    payload = {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"[RAW EVIDENCE START]\n{request.prompt}\n[RAW EVIDENCE END]"}
        ],
        "temperature": 0.1,
        "n_predict": 1024,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "niem_extraction",
                "strict": True,
                "schema": NIEM_JSON_SCHEMA
            }
        }
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(LLAMA_API_URL, json=payload, timeout=120.0)
            response.raise_for_status()
            result = response.json()
            # The output is mathematically guaranteed to be valid JSON formatted to NIEM specs
            extracted_data = json.loads(result["choices"][0]["message"]["content"])

            # Zero-Knowledge logging (body/query text is strictly excluded)
            audit_logger.info(f"Event: LLM_Extraction_Complete | Status: Success")

            return {"status": "success", "data": extracted_data}

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=500, detail=f"Inference engine error: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Middleware Communication Error: {str(e)}")

@app.post("/api/export_markdown", dependencies=[Depends(verify_cjis_attributes)])
async def export_to_markdown(request: ExportRequest):
    timestamp = datetime.date.today().isoformat()

    # SECURITY FIX: Strip all special characters to prevent path traversal
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', request.entity_name.replace(" ", "_"))
    filename = f"{EXPORT_DIR}/Entity_{safe_name}.md"

    markdown_content = f"""---
case_id: UNASSIGNED
entity_type: extracted_entity
aliases: {request.aliases}
date_extracted: {timestamp}
---

# Suspect: [[{request.entity_name}]]

## Known Connections
"""
    for conn in request.connections:
        markdown_content += f"* [[{conn}]]\n"

    markdown_content += f"""
## AI Extraction Summary
{request.summary}

## Chain of Custody Reference
* **Source File:** `{request.source_file}`
"""
    try:
        # ASYNC FIX: Use aiofiles to prevent blocking the FastAPI event loop
        async with aiofiles.open(filename, "w") as f:
            await f.write(markdown_content)

        audit_logger.info(f"Event: KNOWLEDGE_GRAPH_EXPORT | Entity: {safe_name}")
        return JSONResponse(content={"status": "success", "file": filename})

    except Exception as e:
        audit_logger.error(f"Event: EXPORT_ERROR | Detail: {str(e)}")
        raise HTTPException(status_code=500, detail=f"File write failure: {str(e)}")

# ---------------------------------------------------------
# NEW: Database Verification Routes
# ---------------------------------------------------------

@app.post("/api/media/ingest", dependencies=[Depends(verify_cjis_attributes)])
async def ingest_media_to_db(
    case_reference: str = Form(...),
    classification: str = Form(...),
    file: UploadFile = File(...)
):
    """Computes file hashes and permanently adds them to the PostgreSQL database."""
    contents = await file.read()

    # 1. Compute Exact Hash
    sha256_hash = hashlib.sha256(contents).hexdigest()

    # 2. Compute Perceptual Hash (if applicable)
    phash_val = None
    if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
        try:
            img = Image.open(io.BytesIO(contents))
            phash_val = str(imagehash.phash(img))
        except Exception as e:
            audit_logger.error(f"Image processing failed during ingest for {file.filename}: {e}")

    # 3. Insert into Database
    async with db_pool.acquire() as conn:
        # Insert the exact SHA-256 hash
        await conn.execute(
            "INSERT INTO vic_hashes (hash_type, hash_value, classification, case_reference) VALUES ('SHA256', $1, $2, $3)",
            sha256_hash, classification, case_reference
        )

        # Insert the perceptual hash if it was generated
        if phash_val:
            await conn.execute(
                "INSERT INTO vic_hashes (hash_type, hash_value, classification, case_reference) VALUES ('PHASH', $1, $2, $3)",
                phash_val, classification, case_reference
            )

    # 4. Zero-Knowledge Audit Log
    audit_logger.info(f"Event: DATABASE_INGEST | Case: {case_reference} | Classification: {classification}")

    return {
        "status": "SUCCESS",
        "message": f"Hashes for {file.filename} permanently added to local VIC database."
    }

@app.post("/api/hashes/verify", dependencies=[Depends(verify_cjis_attributes)])
async def verify_hash_backend(request: HashVerifyRequest):
    """Used by the local watchdog pipeline to verify a hash against PostgreSQL."""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT classification, case_reference FROM vic_hashes WHERE hash_type = $1 AND hash_value = $2",
            request.hash_type, request.hash_value
        )
        if row:
            audit_logger.critical(f"Event: VIC_MATCH | Hash: {request.hash_value} | Case: {row['case_reference']}")
            return {"match": True, "classification": row["classification"], "case": row["case_reference"]}
        return {"match": False}

@app.post("/api/media/upload", dependencies=[Depends(verify_cjis_attributes)])
async def process_media_upload(file: UploadFile = File(...)):
    """Used by the Web UI Drag-and-Drop. Hashes in memory, checks DB, discards file."""
    contents = await file.read()

    # Compute Exact Hash
    sha256_hash = hashlib.sha256(contents).hexdigest()

    # Compute Perceptual Hash if Image
    phash_val = None
    if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
        try:
            img = Image.open(io.BytesIO(contents))
            phash_val = str(imagehash.phash(img))
        except Exception as e:
            audit_logger.error(f"Image processing failed for {file.filename}: {e}")

    # Check Database
    async with db_pool.acquire() as conn:
        # Check Exact First
        row = await conn.fetchrow(
            "SELECT case_reference FROM vic_hashes WHERE hash_type = 'SHA256' AND hash_value = $1",
            sha256_hash
        )
        if row:
            return {"status": "MATCH", "type": "SHA256", "case": row["case_reference"], "filename": file.filename}

        # Check Perceptual Second
        if phash_val:
            row = await conn.fetchrow(
                "SELECT case_reference FROM vic_hashes WHERE hash_type = 'PHASH' AND hash_value = $1",
                phash_val
            )
            if row:
                return {"status": "MATCH", "type": "PHASH", "case": row["case_reference"], "filename": file.filename}

    return {"status": "CLEARED", "filename": file.filename}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
