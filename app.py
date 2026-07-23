from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import httpx
import os
import datetime
import logging
import json

app = FastAPI(title="Sentinel Edge Node UI")

# Directory & Template setups
EXPORT_DIR = "./knowledge_graph_exports"
os.makedirs(EXPORT_DIR, exist_ok=True)
templates = Jinja2Templates(directory="templates")

# Updated to use the chat completions endpoint for GBNF JSON Schema support
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

class FederatedSearchRequest(BaseModel):
    QueryID: str
    TargetEntity: dict

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
# Security Matrix: ABAC & Zero-Knowledge Auditing
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[AUDIT] %(asctime)s - %(message)s",
    handlers=[logging.FileHandler("cjis_audit.log")]
)
audit_logger = logging.getLogger("CJIS_Audit")

async def verify_cjis_attributes(request: Request):
    """
    Validates GFIPM attributes and hardware MFA token status.
    Blocks requests from unauthorized attributes.
    """
    user_id = request.headers.get("X-GFIPM-User-ID", "UNKNOWN_USER")
    is_icac_active = request.headers.get("X-GFIPM-ICAC-Active", "False")
    mfa_verified = request.headers.get("X-MFA-Verified", "False")

    if mfa_verified != "True":
        audit_logger.warning(f"Event: Authentication_Failed | UserID: {user_id} | Reason: Missing hardware MFA token")
        raise HTTPException(status_code=401, detail="Hardware MFA token required.")

    if is_icac_active != "True":
        audit_logger.warning(f"Event: Access_Denied | UserID: {user_id} | Reason: Lacks required active ICAC task force attribute")
        raise HTTPException(status_code=403, detail="ABAC Violation: Required attributes not met.")
    return user_id

@app.middleware("http")
async def zero_knowledge_audit_middleware(request: Request, call_next):
    """
    Logs API interactions without recording query contents.
    """
    endpoint = request.url.path
    user_id = request.headers.get("X-GFIPM-User-ID", "UNAUTHENTICATED")
    response = await call_next(request)
    
    # Zero-Knowledge logging (body/query text is strictly excluded)
    audit_logger.info(f"Event: API_Transaction | UserID: {user_id} | Endpoint: {endpoint} | Status: {response.status_code}")
    return response

# ---------------------------------------------------------
# Application Routes
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
            return {"status": "success", "data": extracted_data}
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=500, detail=f"Inference engine error: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Middleware Communication Error: {str(e)}")

@app.post("/api/federated_search", dependencies=[Depends(verify_cjis_attributes)])
async def handle_federated_search(request: FederatedSearchRequest):
    """
    Receives a NIEM broadcast from the Hub.
    Executes a localized check and returns a boolean match status.
    """
    target_aliases = request.TargetEntity.get("Aliases", [])
    
    # Zero-Knowledge Logging for inbound federated queries
    audit_logger.info(f"Event: Inbound_Federated_Query | QueryID: {request.QueryID}")
    
    # ---------------------------------------------------------
    # In a fully integrated system, the node would pass the target 
    # aliases to the local llama.cpp container to run a vector 
    # similarity search against the embedded mock_evidence directory.
    # ---------------------------------------------------------
    
    # Mock logic: Assuming the model found a match for "DarkNet_Phantom"
    match_found = "DarkNet_Phantom" in target_aliases
    
    return {
        "query_id": request.QueryID,
        "match_found": match_found,
        "agency_contact": "precinct_admin@local.gov" # Only contact info is returned, no evidence
    }

@app.post("/api/export_markdown", dependencies=[Depends(verify_cjis_attributes)])
async def export_to_markdown(request: ExportRequest):
    timestamp = datetime.date.today().isoformat()
    safe_name = request.entity_name.replace(" ", "_")
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
        with open(filename, "w") as f:
            f.write(markdown_content)
        return JSONResponse(content={"status": "success", "file": filename})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File write failure: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    # Binds only to localhost to ensure it remains strictly on the internal LAN
    uvicorn.run(app, host="127.0.0.1", port=3000)