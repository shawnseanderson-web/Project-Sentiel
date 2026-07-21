from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel
import httpx
import asyncio
import logging

app = FastAPI(title="Sentinel Federated Search Broker (Hub)")

# Audit Logging (Zero-Knowledge)
logging.basicConfig(level=logging.INFO, format="[HUB AUDIT] %(asctime)s - %(message)s")
logger = logging.getLogger("Hub_Audit")

# Mock Registry of connected Edge Nodes (Spokes)
# In production, nodes would register dynamically via mutual TLS
REGISTERED_EDGE_NODES = [
    "http://127.0.0.1:3000", # Our local test node
    # "http://node-b.precinct2.local:3000",
]

class FederatedQuery(BaseModel):
    query_id: str
    initiating_user: str
    target_alias: str

def generate_niem_payload(query: FederatedQuery) -> dict:
    """Translates the proprietary query into a NIEM-compliant JSON-LD payload."""
    return {
        "@context": {
            "nc": "http://release.niem.gov/niem/niem-core/5.0/#",
            "Aliases": "nc:UserOnlineAliasIdentity"
        },
        "QueryID": query.query_id,
        "TargetEntity": {
            "Aliases": [query.target_alias]
        }
    }

async def forward_to_node(client: httpx.AsyncClient, node_url: str, payload: dict, headers: dict):
    """Fires the NIEM payload to a single edge node."""
    try:
        # Assuming the edge node will have an endpoint /api/federated_search
        response = await client.post(
            f"{node_url}/api/federated_search", 
            json=payload, 
            headers=headers,
            timeout=30.0
        )
        if response.status_code == 200:
            return {"node": node_url, "status": "success", "data": response.json()}
        return {"node": node_url, "status": "failed", "code": response.status_code}
    except Exception as e:
        return {"node": node_url, "status": "offline", "error": str(e)}

@app.post("/api/broker/broadcast")
async def broadcast_query(request: Request, query: FederatedQuery):
    """
    Receives a search request, translates to NIEM, and broadcasts to all edge nodes.
    """
    # 1. Security Check & Zero-Knowledge Audit
    mfa_verified = request.headers.get("X-MFA-Verified", "False")
    if mfa_verified != "True":
        logger.warning(f"Event: Broadcast_Rejected | User: {query.initiating_user} | Reason: Missing MFA")
        raise HTTPException(status_code=401, detail="Hardware MFA token required at Hub.")
        
    logger.info(f"Event: Broadcast_Initiated | QueryID: {query.query_id} | User: {query.initiating_user}")

    # 2. Translate to NIEM standard
    niem_payload = generate_niem_payload(query)
    
    # Pass along the GFIPM headers to ensure ABAC works at the Edge Node level
    forwarding_headers = {
        "X-MFA-Verified": "True",
        "X-GFIPM-User-ID": query.initiating_user,
        "X-GFIPM-ICAC-Active": request.headers.get("X-GFIPM-ICAC-Active", "False")
    }

    # 3. Asynchronous Broadcast using httpx
    results = []
    async with httpx.AsyncClient() as client:
        tasks = [
            forward_to_node(client, node_url, niem_payload, forwarding_headers)
            for node_url in REGISTERED_EDGE_NODES
        ]
        # Gather responses from all nodes concurrently
        results = await asyncio.gather(*tasks)

    # 4. Aggregate Tally
    successful_hits = [res for res in results if res["status"] == "success" and res.get("data", {}).get("match_found")]
    
    logger.info(f"Event: Broadcast_Completed | QueryID: {query.query_id} | Hits: {len(successful_hits)}")
    
    return {
        "query_id": query.query_id,
        "nodes_queried": len(REGISTERED_EDGE_NODES),
        "positive_hits": len(successful_hits),
        "details": results
    }

if __name__ == "__main__":
    import uvicorn
    # Hub runs on port 5000 to differentiate from the Edge Node (3000)
    uvicorn.run(app, host="0.0.0.0", port=5000)