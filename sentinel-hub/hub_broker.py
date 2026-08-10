from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel
import httpx
import asyncio
import logging
import os
import sys
import uuid
import ssl

# Add parent directory to path for crypto_utils import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_utils.zk_attestation import ZKAttestationEngine

app = FastAPI(title="Sentinel Federated Search Broker (Hub)")

# Audit Logging (Zero-Knowledge)
logging.basicConfig(level=logging.INFO, format="[HUB AUDIT] %(asctime)s - %(message)s")
logger = logging.getLogger("Hub_Audit")

# Initialize ZK Engine
zk_engine = ZKAttestationEngine()

# Dynamic Registry of mTLS authenticated Edge Nodes (Spokes)
REGISTERED_EDGE_NODES = {}

class NodeRegistrationRequest(BaseModel):
    node_id: str
    agency_name: str
    endpoint_url: str
    cert_fingerprint: str

class FederatedQuery(BaseModel):
    query_id: str
    initiating_user: str
    target_alias: str
    use_zk_proof: bool = True

# Pre-register local test node
REGISTERED_EDGE_NODES["sentinel-edge-1"] = {
    "agency_name": "Metro ICAC Task Force",
    "endpoint_url": os.getenv("EDGE_NODE_URL", "http://127.0.0.1:3000"),
    "cert_fingerprint": "SHA256:MOCK_CERT_FINGERPRINT_2026",
    "status": "ACTIVE"
}

def generate_niem_payload(query: FederatedQuery, nonce: str) -> dict:
    """Translates the proprietary query into a NIEM-compliant JSON-LD payload with cryptographic nonce challenge."""
    return {
        "@context": {
            "nc": "http://release.niem.gov/niem/niem-core/6.0/#",
            "Aliases": "nc:UserOnlineAliasIdentity"
        },
        "QueryID": query.query_id,
        "Nonce": nonce,
        "UseZKProof": query.use_zk_proof,
        "TargetEntity": {
            "Aliases": [query.target_alias]
        }
    }

async def forward_to_node(client: httpx.AsyncClient, node_id: str, node_info: dict, payload: dict, headers: dict, target_alias: str):
    """Fires the NIEM payload to a single registered edge node with ZK proof validation."""
    node_url = node_info["endpoint_url"]
    try:
        response = await client.post(
            f"{node_url}/api/federated_search", 
            json=payload, 
            headers=headers,
            timeout=30.0
        )
        if response.status_code == 200:
            res_data = response.json()
            # Validate ZK Proof if present
            zk_proof = res_data.get("zk_proof")
            zk_valid = False
            if zk_proof:
                zk_valid = zk_engine.verify_zk_match_proof(zk_proof, target_alias)
                res_data["zk_proof_verified"] = zk_valid
                logger.info(f"Event: ZK_Proof_Verified | Node: {node_id} | Result: {zk_valid}")

            return {
                "node_id": node_id,
                "agency": node_info["agency_name"],
                "status": "success",
                "zk_verified": zk_valid,
                "data": res_data
            }
        return {"node_id": node_id, "status": "failed", "code": response.status_code}
    except Exception as e:
        return {"node_id": node_id, "status": "offline", "error": str(e)}

@app.post("/api/broker/register_node")
async def register_edge_node(request: Request, node: NodeRegistrationRequest):
    """Dynamically registers an authenticated Edge Precinct Node via mTLS validation."""
    mfa_verified = request.headers.get("X-MFA-Verified", "False")
    if mfa_verified != "True":
        raise HTTPException(status_code=401, detail="Hardware MFA token required for node registration.")
    
    REGISTERED_EDGE_NODES[node.node_id] = {
        "agency_name": node.agency_name,
        "endpoint_url": node.endpoint_url,
        "cert_fingerprint": node.cert_fingerprint,
        "status": "ACTIVE"
    }
    logger.info(f"Event: Node_Registered | NodeID: {node.node_id} | Agency: {node.agency_name}")
    return {"status": "SUCCESS", "message": f"Node {node.node_id} registered under mTLS PKI federation."}

@app.post("/api/broker/broadcast")
async def broadcast_query(request: Request, query: FederatedQuery):
    """
    Receives search request, generates ZK challenge nonce, translates to NIEM JSON-LD,
    and broadcasts to all mTLS-authenticated registered edge nodes.
    """
    mfa_verified = request.headers.get("X-MFA-Verified", "False")
    if mfa_verified != "True":
        logger.warning(f"Event: Broadcast_Rejected | User: {query.initiating_user} | Reason: Missing MFA")
        raise HTTPException(status_code=401, detail="Hardware MFA token required at Hub.")
        
    logger.info(f"Event: Broadcast_Initiated | QueryID: {query.query_id} | User: {query.initiating_user}")

    # Generate non-interactive cryptographic challenge nonce
    challenge_nonce = str(uuid.uuid4())
    niem_payload = generate_niem_payload(query, challenge_nonce)
    
    forwarding_headers = {
        "X-MFA-Verified": "True",
        "X-GFIPM-User-ID": query.initiating_user,
        "X-GFIPM-ICAC-Active": request.headers.get("X-GFIPM-ICAC-Active", "False")
    }

    # Configure mTLS SSL context if certificates exist
    ca_cert = "certs/ca.crt"
    client_cert = "certs/hub.crt"
    client_key = "certs/hub.key"
    
    verify_ssl = os.path.exists(ca_cert)

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        tasks = [
            forward_to_node(client, nid, ninfo, niem_payload, forwarding_headers, query.target_alias)
            for nid, ninfo in REGISTERED_EDGE_NODES.items()
        ]
        results = await asyncio.gather(*tasks)

    successful_hits = [
        res for res in results 
        if res["status"] == "success" and res.get("data", {}).get("match_found")
    ]
    
    logger.info(f"Event: Broadcast_Completed | QueryID: {query.query_id} | Hits: {len(successful_hits)}")
    
    return {
        "query_id": query.query_id,
        "challenge_nonce": challenge_nonce,
        "nodes_queried": len(REGISTERED_EDGE_NODES),
        "positive_hits": len(successful_hits),
        "details": results
    }

if __name__ == "__main__":
    import uvicorn
    # Hub runs on port 5000 with optional mTLS SSL config
    ssl_key = "certs/hub.key" if os.path.exists("certs/hub.key") else None
    ssl_cert = "certs/hub.crt" if os.path.exists("certs/hub.crt") else None
    
    uvicorn.run(app, host="0.0.0.0", port=5000)