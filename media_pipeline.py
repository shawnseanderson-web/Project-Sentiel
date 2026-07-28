import os
import time
import hashlib
import logging
import httpx
from PIL import Image
import imagehash
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO, format="[MEDIA PIPELINE] %(asctime)s - %(message)s")
logger = logging.getLogger("VIC_Pipeline")

EVIDENCE_DIR = "./mock_evidence"
# Internal docker network URL for the API
API_VERIFY_URL = "http://middleware-ui:3000/api/hashes/verify"

# Required for the Zero-Knowledge middleware
AUTH_HEADERS = {
    'X-MFA-Verified': 'True',
    'X-GFIPM-ICAC-Active': 'True',
    'X-GFIPM-User-ID': 'Watchdog_Service'
}

def query_database(hash_type, hash_value):
    try:
        response = httpx.post(
            API_VERIFY_URL,
            json={"hash_type": hash_type, "hash_value": hash_value},
            headers=AUTH_HEADERS,
            timeout=10.0
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error(f"Database query failed: {e}")
    return {"match": False}

class EvidenceHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        logger.info(f"New evidence detected: {event.src_path}. Initiating triage...")
        self.process_file(event.src_path)

    def process_file(self, filepath):
        try:
            # 1. Cryptographic Hash (SHA-256)
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            exact_hash = sha256_hash.hexdigest()

            # Check Database for Exact Match
            result = query_database("SHA256", exact_hash)
            if result.get("match"):
                logger.critical(f"🚨 EXACT MATCH (SHA-256). Linked to Case: {result['case']}")
                return

            # 2. Perceptual Hash (pHash)
            if filepath.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                img = Image.open(filepath)
                phash_val = str(imagehash.phash(img))

                # Check Database for Perceptual Match
                result = query_database("PHASH", phash_val)
                if result.get("match"):
                    logger.critical(f"🚨 PERCEPTUAL MATCH (pHash). Linked to Case: {result['case']}")
                    return

            logger.info("File cleared triage. Ready for AI review.")

        except Exception as e:
            logger.error(f"Error processing {filepath}: {str(e)}")

if __name__ == "__main__":
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    event_handler = EvidenceHandler()
    observer = Observer()
    observer.schedule(event_handler, EVIDENCE_DIR, recursive=True)

    logger.info(f"Media Pipeline active. Monitoring {EVIDENCE_DIR}...")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
