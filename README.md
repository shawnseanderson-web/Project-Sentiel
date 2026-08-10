# Project Sentinel: Federated Intelligence Network

**Project Sentinel** is a secure, decentralized, and federated artificial intelligence and search broker network designed for law enforcement. It enables localized, low-resource agencies to collaborate on complex investigations by sharing machine learning insights without ever centralizing, copying, or transmitting sensitive restricted case files or illicit media.

This repository contains the complete **Phase 1-3** implementation along with **Phase 4 Security, Edge Intelligence & Graph Analysis Enhancements**, featuring:
* Local Edge Inference Node (Spoke) & PostgreSQL VIC Hash Database
* Embedded Graph Engine & Multi-Hop Link Analysis (`graph_engine/`)
* Cross-Precinct Alias Disambiguation & Entity Resolution (`sentinel_graph.py`)
* Embedded Vector Database & Semantic Evidence RAG Engine (`vector_rag/`)
* On-Device Multimodal Vision (VLM) Triage for Unindexed Media (`media_pipeline.py`)
* Central Federated Search Broker (Hub) with Zero-Knowledge (ZK-SNARK) Attestations
* Mutual TLS (mTLS) Public Key Infrastructure (PKI) for authenticated precinct node identity
* Secure Multi-Party Computation (SecAgg) Flower Federated Learning with Local Differential Privacy
* Project VIC automated media watchdog pipeline

---

## 🏗️ System Architecture

The system utilizes a hub-and-spoke model to ensure evidence never leaves the local precinct.
  
*   **Local Inference Engine (Spoke):** Runs hardware-accelerated inference locally inside a Docker container (powered by `llama-server` / Vulkan). Supports both standard GGUF 4-bit models and experimental 1-bit architectures.
*   **Edge Security & Search Middleware:** A FastAPI API (`app.py`) enforcing Attribute-Based Access Control (ABAC) via GFIPM headers, zero-knowledge tamper-evident auditing, NIEM schema compliance, Obsidian knowledge graph Markdown exports, embedded RAG vector search, multi-hop graph analysis, and federated query handling.
*   **Embedded Graph Engine & Multi-Hop Search:** Micro-engine (`graph_engine/sentinel_graph.py`) that stores entity nodes and relationships in SQLite (`sentinel_graph.db`). Supports multi-hop link analysis (`/api/graph/multi_hop_search`) to traverse connections across suspect records, vehicles, and phone numbers.
*   **Automated Alias Resolution & Entity Disambiguation:** Uses Jaro-Winkler string similarity and Levenshtein edit distance (`/api/graph/resolve_aliases`) to automatically group and merge duplicate entity records (e.g. `"Johnathan Doe"` and `"Johnny Doe"`) into master suspect nodes.
*   **Embedded Vector Database & Semantic RAG Engine:** Local micro-engine (`vector_rag/evidence_vector_db.py`) that indexes case files, notes, and exports into a local SQLite vector store (`sentinel_rag.db`) for semantic similarity search (`/api/rag/search`).
*   **Multimodal Vision (VLM) Media Triage:** On-device visual inspection in `media_pipeline.py` (`/api/vlm/inspect_media`) that analyzes visual entropy, image resolution, and feature indicators for unindexed media clearing exact/perceptual hash database checks.
*   **Zero-Knowledge Proof Attestations:** Micro-engine (`crypto_utils/zk_attestation.py`) that generates Pedersen-like cryptographic commitments and ZK match proofs for federated queries. Edge nodes mathematically prove a match exists without revealing suspect names or file paths until legal warrants are verified.
*   **mTLS PKI Node Identity:** Precinct nodes and central broker authenticate via mutual TLS using x.509 certificates (`certs/`) signed by a trusted Law Enforcement CA root.
*   **PostgreSQL VIC Hash Database:** A dedicated PostgreSQL database (`sentinel-postgres`) storing cryptographic (SHA-256) and perceptual (`pHash`) hashes for exact and near-duplicate illicit media detection.
*   **Media Pipeline Watchdog:** A local service (`media_pipeline.py`) running inside Docker that monitors evidence directories, computes cryptographic/perceptual hashes, runs zero-shot VLM inspection, and queries PostgreSQL before LLM processing occurs.
*   **Central Search Broker (Hub):** An orchestration service (`sentinel-hub/hub_broker.py`) hosted in the cloud/central network. It translates requests into NIEM JSON-LD payloads, generates non-interactive challenge nonces, and verifies ZK match proofs from mTLS-authenticated edge nodes.
*   **Secure Aggregation (SecAgg) Federated Learning:** Uses the Flower (`flwr`) framework (`flower_client.py` and `flower_server.py`) with Local Differential Privacy and Secure Aggregation (cryptographic weight masking) to aggregate global model updates without central weight leakage.

---

## 📁 Repository Structure

```text
Project_Sentinel/
├── Dockerfile                  # Mainline build for standard GGUF 4-bit models (llama-server)
├── Dockerfile.1bit             # Custom build for 1-bit / 1.58-bit Ternary models
├── Dockerfile.services         # Python runtime environment for middleware and media pipeline
├── docker-compose.yml          # Multi-container orchestration (DB, LLM, Middleware, Watchdog)
├── app.py                      # Edge Node FastAPI service (ABAC, ZK Proofs, RAG Search, Graph Analysis)
├── media_pipeline.py           # Watchdog monitoring mock_evidence for SHA-256, pHash & VLM inspection
├── flower_client.py            # Local Edge Node federated learning client with Local DP & mTLS
├── flower_server.py            # Central Hub Flower SecAgg aggregation server with mTLS gRPC
├── init.sql                    # PostgreSQL initialization script for vic_hashes table schema
├── graph_engine/
│   └── sentinel_graph.py       # Embedded SQLite Graph Engine & Jaro-Winkler/Levenshtein Alias Resolver
├── vector_rag/
│   └── evidence_vector_db.py   # Embedded SQLite Vector Database & RAG semantic search engine
├── crypto_utils/
│   └── zk_attestation.py       # Zero-Knowledge Proof (ZK-SNARK Lite) commitment & verification engine
├── certs/
│   ├── ca.crt                  # Law Enforcement Root Certificate Authority
│   ├── hub.crt / hub.key       # Central Hub mTLS certificate & key
│   └── edge_node.crt / .key    # Precinct Edge Node mTLS certificate & key
├── sentinel-hub/
│   ├── hub_broker.py           # Central Broker API (mTLS node registration & ZK proof validation)
│   └── JSON.LD                 # NIEM JSON-LD context schema definition
├── templates/
│   └── index.html              # Investigator Web UI (Split-pane terminal, drag-and-drop media triage)
├── mock_evidence/              # (Mounted read-only) Case file drop folder for automated triage
├── knowledge_graph_exports/    # (Generated dynamically) Destination for Obsidian-ready .md exports
├── models/                     # (Local mount) Storage directory for GGUF model binaries
└── cjis_audit.log              # Zero-knowledge tamper-evident log generated by middleware
```ounted read-only) Case file drop folder for automated triage
├── knowledge_graph_exports/    # (Generated dynamically) Destination for Obsidian-ready .md exports
├── models/                     # (Local mount) Storage directory for GGUF model binaries
└── cjis_audit.log              # Zero-knowledge tamper-evident log generated by middleware
```

---

## 🚀 Prerequisites

*   **Docker & Docker Compose**
*   **Python 3.9+** (For standalone script testing or host execution)
*   **Vulkan / GPU Drivers** (Optional, required for GPU acceleration in `inference-engine`)

---

## 🛠️ Installation & Deployment

### 1. Pre-Flight File & Directory Initialization
Before starting Docker Compose, initialize the required volume directories and log files:

```bash
mkdir -p models mock_evidence knowledge_graph_exports && touch cjis_audit.log mock_vics_database.json
```

### 2. Configure Environment (Optional)
You can customize PostgreSQL credentials and service endpoints using environment variables or a local `.env` file:
```bash
export POSTGRES_USER=sentinel_admin
export POSTGRES_PASSWORD=secure_local_password
export POSTGRES_DB=vic_hashes
export DATABASE_URL=postgresql://sentinel_admin:secure_local_password@sentinel-db:5432/vic_hashes
export LLAMA_API_URL=http://inference-engine:8080/completion
```

---

## 🕹️ Deployment Operations

### Option A: Complete Unified Edge Node (Recommended)
Boots PostgreSQL, the Inference Engine, Middleware Web UI, and the Media Watchdog.

1. Place your `.gguf` model file inside the `./models/` directory (e.g. `qwen2.5-coder-7b-instruct-ghidra-v2-q4_k_m.gguf`).
2. Launch the stack:
   ```bash
   docker-compose up --build
   ```
3. Access the Investigator Web UI at `http://localhost:3000`.

### Option B: Federated Search Broker (Hub Execution)
To test cross-precinct federated searching:

1. Launch the Central Hub Broker:
   ```bash
   python sentinel-hub/hub_broker.py
   ```
2. Send a federated broadcast request (requires valid `X-MFA-Verified: True` header):
   ```bash
   curl -X POST http://localhost:5000/api/broker/broadcast \
     -H "Content-Type: application/json" \
     -H "X-MFA-Verified: True" \
     -H "X-GFIPM-ICAC-Active: True" \
     -d '{
       "query_id": "Q-2026-001",
       "initiating_user": "DET_SMITH_994",
       "target_alias": "BlackHat_99"
     }'
   ```

### Option C: Federated Learning & Differential Privacy
To simulate privacy-preserving weight aggregation:

1. Start the Flower Aggregation Server:
   ```bash
   python flower_server.py
   ```
2. In a separate terminal, launch the Edge Node Client:
   ```bash
   python flower_client.py
   ```

---

## 🔄 Data Flow Architecture

```text
[Investigator Web UI / Hub Broker]
        │ (HTTP REST with GFIPM ABAC Headers via Port 3000)
        ▼
[middleware-ui Container (app.py)]
        │
        ├─► [sentinel-db (PostgreSQL)] (Hashes ingest & verification)
        │
        ├─► Converts NIEM JSON Schema -> GBNF Logit Constraints
        │   Enforces low-temperature extraction (0.1)
        ▼
[inference-engine Container (llama-server)]
        │
        │ Extracts raw structured entities matching "nc:" fields
        ▼
[middleware-ui Container (app.py)]
        │
        │ Generates sanitized Obsidian Markdown files (.md)
        ▼
[knowledge_graph_exports/ Folder]
```

---

## 🔒 Security & CJIS Compliance Matrix

*   **GFIPM Identity Federation:** Every API endpoint verifies hardware MFA (`X-MFA-Verified: True`) and role attributes (`X-GFIPM-ICAC-Active: True`).
*   **Zero-Knowledge Audit Trail:** Middleware automatically writes transaction records to `cjis_audit.log` while explicitly excluding case text or query content.
*   **Immutable Evidence Mounts:** Source case evidence directories are mounted as read-only (`:ro`) volumes in all containers.
*   **Local Differential Privacy:** Federated updates clip weight gradients and inject Gaussian noise to prevent target data reconstruction.
