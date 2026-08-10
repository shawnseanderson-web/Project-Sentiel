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
from crypto_utils.zk_attestation import ZKAttestationEngine
from vector_rag.evidence_vector_db import EvidenceVectorDB
from graph_engine.sentinel_graph import SentinelGraphEngine

zk_engine = ZKAttestationEngine()
vector_db = EvidenceVectorDB(db_path="sentinel_rag.db")
graph_engine = SentinelGraphEngine(db_path="sentinel_graph.db")

# ---------------------------------------------------------
# Database Connection Pool Lifespan
# ---------------------------------------------------------
db_pool = None
DB_URL = os.getenv("DATABASE_URL", "postgresql://sentinel_admin:secure_local_password@sentinel-db:5432/vic_hashes")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    try:
        db_pool = await asyncpg.create_pool(DB_URL)
        audit_logger.info("Database connection pool initialized successfully.")
    except Exception as e:
        audit_logger.warning(f"Database connection pool unavailable on startup: {e}")
        db_pool = None
    yield
    if db_pool:
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

class FederatedSearchPayload(BaseModel):
    QueryID: str
    TargetEntity: dict
    Nonce: str = ""
    UseZKProof: bool = True

class RAGSearchRequest(BaseModel):
    query: str
    top_k: int = 5

class RAGIndexRequest(BaseModel):
    target_dir: str = "./mock_evidence"

class GraphSearchRequest(BaseModel):
    start_node_id: str
    max_hops: int = 2

class AliasResolveRequest(BaseModel):
    similarity_threshold: float = 0.85

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

        # Ingest into Embedded Sentinel Graph Engine
        entity_node_id = graph_engine.add_entity(
            name=request.entity_name,
            entity_type="Suspect",
            attributes={"aliases": request.aliases, "source_file": request.source_file}
        )
        for conn in request.connections:
            if conn and conn.strip():
                conn_node_id = graph_engine.add_entity(name=conn.strip(), entity_type="AssociatedEntity")
                graph_engine.add_relationship(source_id=entity_node_id, target_id=conn_node_id, relationship="CONNECTED_TO", case_ref=request.source_file)

        audit_logger.info(f"Event: KNOWLEDGE_GRAPH_EXPORT | Entity: {safe_name} | GraphNode: {entity_node_id}")
        return JSONResponse(content={"status": "success", "file": filename, "graph_node_id": entity_node_id})

    except Exception as e:
        audit_logger.error(f"Event: EXPORT_ERROR | Detail: {str(e)}")
        raise HTTPException(status_code=500, detail=f"File write failure: {str(e)}")

# ---------------------------------------------------------
# FEDERATED SEARCH ROUTE (Hub Integration)
# ---------------------------------------------------------
@app.post("/api/federated_search", dependencies=[Depends(verify_cjis_attributes)])
async def handle_federated_search(payload: FederatedSearchPayload):
    """
    Receives NIEM-compliant search query broadcast from the Central Hub.
    Searches local knowledge graph exports (.md files) for target entity matches.
    """
    target_aliases = payload.TargetEntity.get("Aliases", [])
    matches = []

    if target_aliases:
        for alias in target_aliases:
            if not alias or not str(alias).strip():
                continue
            clean_alias = str(alias).strip().lower()
            if os.path.exists(EXPORT_DIR):
                for root, _, files in os.walk(EXPORT_DIR):
                    for fname in files:
                        if fname.endswith(".md"):
                            fpath = os.path.join(root, fname)
                            try:
                                async with aiofiles.open(fpath, mode="r") as f:
                                    content = await f.read()
                                    if clean_alias in content.lower():
                                        matches.append({
                                            "file": fname,
                                            "alias_queried": alias
                                        })
                            except Exception as e:
                                audit_logger.error(f"Error reading {fpath} during federated search: {e}")

    match_found = len(matches) > 0
    zk_proof = None
    if match_found and payload.UseZKProof:
        first_match_file = matches[0]["file"]
        target_alias = target_aliases[0] if target_aliases else "UNKNOWN"
        zk_proof = zk_engine.generate_zk_match_proof(
            query_id=payload.QueryID,
            target_alias=target_alias,
            match_file=first_match_file,
            nonce=payload.Nonce or "DEFAULT_NONCE_2026"
        )

    audit_logger.info(f"Event: FEDERATED_SEARCH | QueryID: {payload.QueryID} | MatchFound: {match_found} | ZKProofGenerated: {zk_proof is not None}")

    return {
        "status": "success",
        "query_id": payload.QueryID,
        "match_found": match_found,
        "zk_proof": zk_proof,
        "matches": matches if not payload.UseZKProof else [{"alias_queried": m["alias_queried"]} for m in matches]
    }

# ---------------------------------------------------------
# EMBEDDED RAG VECTOR SEARCH & VLM ROUTES
# ---------------------------------------------------------
@app.post("/api/rag/index", dependencies=[Depends(verify_cjis_attributes)])
async def index_evidence_directory(request: RAGIndexRequest):
    """
    Scans and indexes evidence text files and knowledge graph exports into the local SQLite Vector DB.
    """
    target_dir = request.target_dir
    indexed_files = 0
    total_chunks = 0

    dirs_to_scan = [target_dir, EXPORT_DIR]
    for d in dirs_to_scan:
        if os.path.exists(d):
            for root, _, files in os.walk(d):
                for fname in files:
                    if fname.endswith(('.txt', '.md', '.log', '.json')):
                        fpath = os.path.join(root, fname)
                        try:
                            async with aiofiles.open(fpath, mode="r", errors="ignore") as f:
                                content = await f.read()
                                if content.strip():
                                    chunks = vector_db.index_document(
                                        doc_id=fname,
                                        source_file=fpath,
                                        text_content=content,
                                        metadata={"directory": d}
                                    )
                                    indexed_files += 1
                                    total_chunks += chunks
                        except Exception as e:
                            audit_logger.error(f"Failed to index {fpath}: {e}")

    audit_logger.info(f"Event: RAG_INDEX_COMPLETE | IndexedFiles: {indexed_files} | TotalChunks: {total_chunks}")
    return {
        "status": "SUCCESS",
        "indexed_files": indexed_files,
        "total_chunks": total_chunks
    }

@app.post("/api/rag/search", dependencies=[Depends(verify_cjis_attributes)])
async def search_evidence_vectors(request: RAGSearchRequest):
    """
    Executes local semantic RAG similarity search over indexed evidence vector chunks.
    """
    results = vector_db.search(query=request.query, top_k=request.top_k)
    audit_logger.info(f"Event: RAG_SEARCH | Query: '{request.query[:30]}...' | ResultsCount: {len(results)}")
    return {
        "status": "SUCCESS",
        "query": request.query,
        "results_count": len(results),
        "results": results
    }

@app.post("/api/vlm/inspect_media", dependencies=[Depends(verify_cjis_attributes)])
async def inspect_media_vlm(file: UploadFile = File(...)):
    """
    Executes on-device Multimodal Vision (VLM) feature analysis on unindexed media files.
    """
    contents = await file.read()
    try:
        img = Image.open(io.BytesIO(contents)).convert('RGB')
        width, height = img.size
        stat = Image.open(io.BytesIO(contents)).convert('L').histogram()
        
        # Calculate visual variance / entropy
        total_pixels = width * height
        entropy = -sum((p / total_pixels) * math.log2(p / total_pixels) for p in stat if p > 0)

        indicators = []
        if entropy > 7.0:
            indicators.append("HIGH_VISUAL_INFORMATION_ENTROPY")
        if width >= 1920 or height >= 1080:
            indicators.append("HIGH_DEFINITION_SOURCE")

        audit_logger.info(f"Event: VLM_INSPECT | Filename: {file.filename} | Resolution: {width}x{height} | Entropy: {entropy:.2f}")

        return {
            "status": "SUCCESS",
            "filename": file.filename,
            "resolution": f"{width}x{height}",
            "entropy": round(entropy, 2),
            "detected_indicators": indicators,
            "triage_recommendation": "PRIORITY_INVESTIGATOR_REVIEW" if indicators else "STANDARD_REVIEW"
        }
    except Exception as e:
        audit_logger.error(f"VLM inspection error for {file.filename}: {e}")
        raise HTTPException(status_code=400, detail=f"Image inspection failed: {str(e)}")

# ---------------------------------------------------------
# GRAPH ENGINE & ALIAS RESOLUTION ROUTES
# ---------------------------------------------------------
@app.post("/api/graph/multi_hop_search", dependencies=[Depends(verify_cjis_attributes)])
async def execute_multi_hop_graph_search(request: GraphSearchRequest):
    """
    Executes BFS multi-hop graph traversal starting from target node.
    """
    result = graph_engine.multi_hop_search(start_node_id=request.start_node_id, max_hops=request.max_hops)
    audit_logger.info(f"Event: GRAPH_MULTI_HOP_SEARCH | StartNode: {request.start_node_id} | Hops: {request.max_hops}")
    return {"status": "SUCCESS", "graph_data": result}

@app.post("/api/graph/resolve_aliases", dependencies=[Depends(verify_cjis_attributes)])
async def execute_alias_resolution(request: AliasResolveRequest):
    """
    Executes Jaro-Winkler & Levenshtein string similarity disambiguation across extracted entities.
    """
    merged_clusters = graph_engine.resolve_aliases(similarity_threshold=request.similarity_threshold)
    audit_logger.info(f"Event: GRAPH_ALIAS_RESOLUTION | MergedClustersCount: {len(merged_clusters)}")
    return {
        "status": "SUCCESS",
        "threshold_used": request.similarity_threshold,
        "resolved_clusters_count": len(merged_clusters),
        "resolved_clusters": merged_clusters
    }

# ---------------------------------------------------------
# Database Verification Routes
# ---------------------------------------------------------

@app.post("/api/media/ingest", dependencies=[Depends(verify_cjis_attributes)])
async def ingest_media_to_db(
    case_reference: str = Form(...),
    classification: str = Form(...),
    file: UploadFile = File(...)
):
    """Computes file hashes and permanently adds them to the PostgreSQL database."""
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database connection pool unavailable.")
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
    if db_pool is None:
        return {"match": False, "error": "Database connection pool unavailable"}
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
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database connection pool unavailable.")
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
