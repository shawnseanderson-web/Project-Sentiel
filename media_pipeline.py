import os
import time
import json
import hashlib
import logging
from PIL import Image
import imagehash
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Zero-Knowledge Audit Configuration
logging.basicConfig(level=logging.INFO, format="[MEDIA PIPELINE] %(asctime)s - %(message)s")
logger = logging.getLogger("VIC_Pipeline")

EVIDENCE_DIR = "./mock_evidence"
VICS_DB_PATH = "./mock_vics_database.json"

def load_vics_database():
    """Loads the local Project VIC hash intelligence."""
    try:
        with open(VICS_DB_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load VICS database: {e}")
        return {"known_hashes": {"exact_sha256": [], "perceptual_phash": []}}

class EvidenceHandler(FileSystemEventHandler):
    def __init__(self, vics_db):
        self.vics_db = vics_db

    def on_created(self, event):
        """Triggered automatically when a new file is dropped into the folder."""
        if event.is_directory:
            return
        
        filepath = event.src_path
        logger.info(f"New evidence detected. Initiating automated triage...")
        self.process_file(filepath)

    def process_file(self, filepath):
        try:
            # 1. Cryptographic Hash (SHA-256) for exact match
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            exact_hash = sha256_hash.hexdigest()

            # 2. Check Exact Match
            if exact_hash in self.vics_db["known_hashes"]["exact_sha256"]:
                logger.critical(f"🚨 VICS EXACT MATCH FOUND (SHA-256). Segregating file.")
                self.flag_for_knowledge_graph("EXACT", exact_hash)
                return

            # 3. Perceptual Hash (pHash) for visual similarity (resizing, cropping)
            # Only process if the file is a valid image format
            if filepath.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                img = Image.open(filepath)
                # pHash generates similar hashes for visually similar content
                phash_val = str(imagehash.phash(img))
                
                # Check Perceptual Match
                if phash_val in self.vics_db["known_hashes"]["perceptual_phash"]:
                    logger.critical(f"🚨 VICS PERCEPTUAL MATCH FOUND (pHash: {phash_val}). Segregating file.")
                    self.flag_for_knowledge_graph("PERCEPTUAL", phash_val)
                    return

            logger.info("File cleared local VICS triage. Ready for AI/Investigator review.")

        except Exception as e:
            logger.error(f"Error processing {filepath}: {str(e)}")

    def flag_for_knowledge_graph(self, match_type, hash_value):
        """
        In a full build, this function automatically generates the Obsidian-ready 
        Markdown file for the known CSAM file without needing LLM text extraction.
        """
        logger.info(f"Node updated: Automatically linked {match_type} match {hash_value} to Knowledge Graph.")

if __name__ == "__main__":
    vics_database = load_vics_database()
    
    # Ensure evidence directory exists
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    
    event_handler = EvidenceHandler(vics_database)
    observer = Observer()
    observer.schedule(event_handler, EVIDENCE_DIR, recursive=True)
    
    logger.info(f"Media Pipeline active. Monitoring {EVIDENCE_DIR} for new evidence...")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()