# Project Sentinel: Federated Intelligence Network

**Project Sentinel** is a secure, decentralized, and federated artificial intelligence search broker designed to allow law enforcement agencies to securely query indexed files across separate servers. It enables localized, low-resource precincts to collaborate on complex investigations by sharing machine learning insights without ever centralizing, copying, or transmitting sensitive restricted case files or illicit media.

This repository contains the complete Phase 1-3 containerized implementation, featuring the local Edge Inference Node (Spoke), the Central Federated Search Broker (Hub), the Project VIC automated media pipeline, and the Flower-based Federated Learning structure with Differential Privacy.

## 🏗️ System Architecture

The system utilizes a hub-and-spoke model to ensure evidence never leaves the local precinct.

   * Local Inference Engine (Spoke): Runs hardware-accelerated inference locally inside a Docker container using llama.cpp and Vulkan. Supports both standard 4-bit models and experimental 1-bit architectures.

   * Central Broker (Hub): An orchestration layer hosted in the cloud. It routes NIEM-compliant search queries and aggregates federated learning model weights.

   * Chain of Custody: The core AI container mounts to investigative evidence folders using immutable, read-only volumes, guaranteeing no technical capability to alter source files.

   * Media Pipeline Automation: A local watchdog script instantly computes hashes of dropped media files and cross-references them against a Project VIC database before linguistic analysis begins.

   * Federated Learning & Differential Privacy: Uses the Flower (flwr) framework to train models locally and share mathematical weights. Differential Privacy injects noise to mathematically guarantee that raw case text cannot be reverse-engineered from the global model.

   * Security Middleware: A FastAPI layer enforcing Attribute-Based Access Control (ABAC) and zero-knowledge tamper-evident auditing for CJIS compliance.

## 🔄 Current Project State & Recent Updates

   * Modernized Docker Runtime: Migrated mainline builds to Ubuntu 22.04 and integrated the official LunarG Vulkan SDK, dropping legacy Mesa graphics dependencies in favor of modern libgl1.

   * Multi-Stage Build Linking: Resolved shared object (.so) linker crashes (exit code 127) by correctly staging and registering libllama-server-impl.so and OpenMP threading libraries (libgomp1) during the container build phase.

   * API Routing: Middleware UI successfully targets internal container hostnames (sentinel-inference-node) to ensure reliable microservice communication.

   * Docker Compose V2: Completely migrated from legacy V1 to the modern docker compose standard.

##📁 Repository Structure

```text
project-sentinel/
├── Dockerfile                  # Mainline Ubuntu 22.04 build with LunarG Vulkan SDK
├── Dockerfile.1bit             # Custom fork build for 1-bit and 1.58-bit Ternary models
├── Dockerfile.services         # Python microservices environment (Pillow/imagehash/FastAPI)
├── docker-compose.yml          # Unified node orchestration stack (Compose V2)
├── app.py                      # Edge Node FastAPI middleware (ABAC routing, NIEM GBNF enforcement)
├── hub_broker.py               # Central Broker API for routing NIEM-compliant federated queries
├── media_pipeline.py           # Automated watchdog for Project VIC perceptual/exact hashing
├── mock_vics_database.json     # Localized database of known exact and perceptual media hashes
├── flower_client.py            # Local Edge Node federated learning client
├── flower_server.py            # Central Hub federated learning aggregation server
├── download_model.py           # Automated Hugging Face GGUF downloader script
├── templates/
│   └── index.html              # Vanilla frontend UI (Split-pane Terminal + Export Module)
├── mock_evidence/              # (Generated dynamically) Read-only simulation of case files
└── knowledge_graph_exports/    # (Generated dynamically) Destination for Obsidian-ready .md exports
```
## 🚀 Prerequisites

   * Docker Compose V2 (Verify by running docker compose version—note the lack of a hyphen)

   * Vulkan Drivers (Optional, but required for local GPU acceleration on the host machine)

   * Python 3.9+ (For isolated staging/script testing)

## 🛠️ Build & Deployment Instructions
### 1. File Initialization & Permission Setup

Before booting the containers, manually create the required local directories and files. Crucially, you must grant the non-root container users the correct host-level permissions to write their audit logs and export files.

Run these commands in your project root:
```Bash

# Create target directories and files
mkdir -p models mock_evidence knowledge_graph_exports
touch cjis_audit.log mock_vics_database.json

# Grant necessary read/write permissions for the container's non-root user
chmod 666 cjis_audit.log
chmod -R 777 knowledge_graph_exports/
```
### 2. Download Model Weights

Use the included script to fetch a compatible GGUF model into your ./models/ directory:
```Bash

pip install huggingface_hub
python download_model.py
```
### 3. Initialize the Media Database

Populate your local mock_vics_database.json file with initial baseline reference hashes to enable the pipeline:
```JSON

{
  "known_media_hashes": [
    {
      "hash_type": "sha256",
      "hash_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "case_reference": "TEST-CASE-001"
    }
  ]
}
```
### 4. Build and Launch the Stack

Use Docker Compose V2 to build the images from scratch and launch the network.

For standard 4-Bit Inference (Recommended):
```Bash

docker compose build --no-cache
docker compose up
```
(Note: If you encounter container naming conflicts from previous aborted builds, run docker compose down first to clear orphaned instances).

Once running, access the Investigator Web UI by navigating your local browser to:
http://localhost:3000

##🕹️ Advanced Operations
### Extreme Edge 1-Bit Inference

To run a specialized 1-bit or ternary model (e.g., PrismML's Bonsai), update your docker-compose.yml to target the custom build file:

   * Change the inference-engine dockerfile: target to Dockerfile.1bit.

   * Update the command arguments to point to your .binary model.

   * Rebuild the stack: docker compose up --build.

###Simulating the Federated Hub

To simulate the network federation and verify Differential Privacy weight aggregation locally:

   * Start the Central Hub Search Broker: python hub_broker.py

   * Start the Flower Aggregation Server: python flower_server.py

   * Execute the training client on the Edge Node: python flower_client.py

## 🔒 Security & CJIS Compliance Matrix

This architecture enforces strict compliance with the FBI's Criminal Justice Information Services (CJIS) standards:

   * Zero-Knowledge Auditing: Both the Edge API and the Hub Broker log every interaction to cjis_audit.log, but strict pre-processing strips the textual parameters of the search itself to protect case integrity.

   * GFIPM Identity Federation: The API checks for valid Multi-Factor Authentication (MFA) and specific active attributes (e.g., active task force assignment) before processing any query.

   * Differential Privacy: The federated learning module utilizes Local DP (noise injection and clipping) to ensure model updates cannot leak individual suspect data.# Project Sentinel: Federated Intelligence Network

