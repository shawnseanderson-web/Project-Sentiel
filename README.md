# Project Sentinel: Federated Intelligence Network

**Project Sentinel** is a secure, decentralized, and federated artificial intelligence and search broker network designed for law enforcement. It enables localized, low-resource agencies to collaborate on complex investigations by sharing machine learning insights without ever centralizing, copying, or transmitting sensitive restricted case files or illicit media.

This repository contains the complete **Phase 1-3** implementation, featuring the local Edge Inference Node (Spoke), the Central Federated Search Broker (Hub), the Project VIC automated media pipeline, and the Flower-based Federated Learning structure with Differential Privacy.

**NOTE:**
This project is in the very early stages and there is no promise it will work but I had an idea and needed
to get as much out as I could before I forgot. This is created entirely in AI and there could be
mistakes. My overall goal, was to provide a way (relatively inexpensively) for Law Enforcement
to be able to check for indexed files on departments servers around the world to assist in the
locating and rescue of child sex abuse victims and children who have been trafficed. 

---

## 🏗️ System Architecture

The system utilizes a hub-and-spoke model to ensure evidence never leaves the local precinct.

*   **Local Inference Engine (Spoke):** Runs `llama.cpp` locally inside a Docker container, optimized for consumer-grade legacy hardware using dynamic compilation for OpenBLAS (CPU) and Vulkan (GPU).
*   **Central Broker (Hub):** An orchestration layer hosted in the cloud. It routes NIEM-compliant search queries and aggregates federated learning model weights.
*   **Chain of Custody:** The core AI container mounts to investigative evidence folders using immutable, read-only volumes, guaranteeing no technical capability to alter source files.
*   **Media Pipeline Automation:** A local watchdog script instantly computes hashes of dropped media files and cross-references them against a Project VIC database before linguistic analysis begins.
*   **Federated Learning & Differential Privacy:** Uses the Flower (`flwr`) framework to train models locally and share mathematical weights. Differential Privacy injects noise to mathematically guarantee that raw case text cannot be reverse-engineered from the global model.
*   **Security Middleware:** A FastAPI layer enforcing Attribute-Based Access Control (ABAC) and zero-knowledge tamper-evident auditing for CJIS compliance.

---

## 📁 Repository Structure

```text
project-sentinel/
├── Dockerfile                  # Multi-stage Alpine build for hardware-accelerated llama.cpp
├── build_and_test.sh           # Automated deployment, hardware mapping, and security testing script
├── app.py                      # Edge Node FastAPI middleware (ABAC routing, Markdown extraction)
├── hub_broker.py               # Central Broker API for routing NIEM-compliant federated queries
├── media_pipeline.py           # Automated watchdog for Project VIC perceptual/exact hashing
├── mock_vics_database.json     # Localized database of known exact and perceptual media hashes
├── flower_client.py            # Local Edge Node federated learning client (with DP noise injection)
├── flower_server.py            # Central Hub federated learning aggregation server
├── templates/
│   └── index.html              # Vanilla frontend UI (Split-pane Terminal + Export Module)
├── mock_evidence/              # (Generated during testing) Read-only simulation of case files
└── knowledge_graph_exports/    # (Generated dynamically) Destination for Obsidian-ready .md exports
```

---

## 🚀 Prerequisites

*   **Docker** (or Podman)
*   **Python 3.9+**
*   **Vulkan Drivers** (Optional, but required for local GPU acceleration on the host machine)

---

## 🛠️ Installation & Setup

### 1. Build and Test the Secure Edge Container
Run the automated testing script to compile the Docker image, map local hardware, stage read-only mock evidence, and execute security tests.
```bash
chmod +x build_and_test.sh
./build_and_test.sh
```

### 2. Install Python Dependencies
Set up your local Python environment to run the middleware, media pipeline, and Flower frameworks.
```bash
pip install fastapi uvicorn httpx pydantic jinja2 watchdog Pillow imagehash flwr numpy
```

### 3. Initialize the Project VIC Media Pipeline
Start the automated watchdog service in the background to monitor the `mock_evidence/` directory for incoming media.
```bash
python media_pipeline.py
```

### 4. Start the Edge Node UI Server
Launch the FastAPI middleware. This binds strictly to localhost to ensure the interface remains isolated on the internal LAN.
```bash
python app.py
```
*Access the investigator dashboard at: `http://127.0.0.1:3000`*

### 5. Start the Central Broker & Federated Learning Hub (For Network Testing)
If you are simulating the full cloud network locally, start the Hub Broker and the Flower Aggregation Server in separate terminal windows.
```bash
python hub_broker.py
python flower_server.py
```

### 6. Connect the Edge Node to the Federation
Execute the training client on your Edge Node to fine-tune the model and securely transmit differentially private updates to the Hub.
```bash
python flower_client.py
```

---

## 🔒 Security & CJIS Compliance Matrix

This application incorporates mock headers to test the strict compliance required by the FBI's Criminal Justice Information Services (CJIS). 

*   **GFIPM Identity Federation:** The API checks for valid Multi-Factor Authentication (MFA) and specific active attributes (e.g., active task force assignment) before processing any query. 
*   **Zero-Knowledge Auditing:** Both `app.py` and `hub_broker.py` log every interaction but strictly strip the textual parameters of the search itself to protect case integrity.
*   **Differential Privacy:** The `flower_client.py` uses Local DP (noise injection and clipping) to ensure model updates cannot leak individual suspect data.
