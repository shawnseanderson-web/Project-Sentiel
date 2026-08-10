# Project Sentinel: Strategic & Technical Improvement Roadmap

This document outlines high-value architectural, security, AI, and standards improvements for **Project Sentinel**, aligned with its mission of secure, privacy-preserving, and federated law enforcement intelligence.

---

## 1. Security, Privacy & Compliance Enhancements

### 🛡️ Zero-Knowledge Proofs (ZK-SNARKs) for Query Attestations
* **Concept:** Replace simple boolean match responses in federated search with Zero-Knowledge proofs.
* **Impact:** Allows an Edge Node to mathematically prove to the Central Hub that a matching suspect, vehicle, or media item exists within its local index *without revealing any identifying metadata or file details* until formal inter-agency legal authorization (e.g., warrant/subpoena sharing) is confirmed.

### 🔑 Hardware Security Module (HSM) & mTLS Node Identity
* **Concept:** Replace the static node registry in `hub_broker.py` with dynamic Mutual TLS (mTLS) registration.
* **Impact:** Each precinct node authenticates using TPM 2.0 or hardware security tokens (e.g., YubiKey) and x.509 certificates signed by a trusted Law Enforcement PKI authority, satisfying strict FBI CJIS policy requirements for node-to-node encryption.

### 🔐 Secure Multi-Party Computation (SecAgg) for Federated Learning
* **Concept:** Integrate Flower’s `SecAgg` protocol alongside Local Differential Privacy.
* **Impact:** Ensures that the Central Hub only sees the aggregated weight changes across $N$ participating precincts. Even if the central server is compromised, individual precinct model updates remain cryptographically masked.

---

## 2. Edge Intelligence & Media Analysis

### 👁️ On-Device Multimodal Vision Models (Zero-Shot Triage)
* **Concept:** Integrate an edge-optimized Vision-Language Model (e.g., Qwen2-VL or MobileVLM) into `media_pipeline.py`.
* **Impact:** While exact SHA-256 and perceptual pHash catch *known* media in the Project VIC database, a local multimodal VLM can perform zero-shot detection on *new/unknown* evidence (e.g., identifying firearms, vehicle license plates, or contraband) entirely offline on precinct hardware.

### 🔍 Local Embedded Vector Database (RAG & Semantic Evidence Search)
* **Concept:** Embed a low-resource vector database (e.g., `ChromaDB` or `DuckDB` with vector search extensions) into the Edge Node container.
* **Impact:** Allows investigators to perform semantic natural language searches across thousands of local unstructured case files (transcripts, OCR scans, investigator notes) prior to NIEM extraction.

---

## 3. Knowledge Graph & Link Analysis

### 🕸️ Embedded Graph Engine for Multi-Hop Link Analysis
* **Concept:** Complement the current Markdown file export with an embedded graph database (e.g., KùzuDB or DuckDB Graph).
* **Impact:** Enables complex multi-hop graph queries (e.g., *"Find all suspects connected to Phone Number X who were also associated with Vehicle Y across cases from 2025–2026"*) without requiring external graph visualization tools like Obsidian.

### 🧩 Automated Cross-Precinct Alias Resolution
* **Concept:** Create an automated entity disambiguation service that calculates string distance (e.g., Jaro-Winkler, Levenshtein) and contextual similarity across extracted NIEM entities.
* **Impact:** Merges duplicate records (e.g., `"Johnathan Doe"`, `"Johnny Doe"`, and `"J. Doe"`) into unified suspect master files automatically.

---

## 4. NIEM Standards & Interoperability

### 📜 Dynamic GBNF Grammar Compiler from NIEM Schemas
* **Concept:** Currently, `NIEM_JSON_SCHEMA` hardcodes Person and Vehicle types in `app.py`. Build a dynamic schema compiler that reads official NIEM XML/JSON-LD schemas on the fly and converts them into GBNF grammars.
* **Impact:** Allows investigators to dynamically select specialized NIEM domains (e.g., Cyber Crime, Human Trafficking, Financial Crime, Incident Reports) for extraction without modifying application code.
