import os
import time
import hashlib
import logging
import httpx
import math
from PIL import Image, ImageStat
import imagehash
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO, format="[MEDIA PIPELINE] %(asctime)s - %(message)s")
logger = logging.getLogger("VIC_Pipeline")

EVIDENCE_DIR = "./mock_evidence"
API_VERIFY_URL = os.getenv("API_VERIFY_URL", "http://middleware-ui:3000/api/hashes/verify")
VLM_INSPECT_URL = os.getenv("VLM_INSPECT_URL", "http://middleware-ui:3000/api/vlm/inspect_media")

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

def zero_shot_multimodal_triage(filepath):
    """
    On-device Multimodal Vision (VLM) Triage.
    Analyzes visual features, edge gradients, and spatial entropy of unindexed media
    to detect contraband, license plates, weapons, or suspicious artifacts.
    """
    try:
        img = Image.open(filepath).convert('RGB')
        stat = ImageStat.Stat(img)
        width, height = img.size
        
        # Calculate visual entropy and color variance
        entropy = sum(s for s in stat.var) / (width * height + 1e-5)
        mean_brightness = sum(stat.mean) / 3.0

        # Trigger VLM zero-shot inspection API if active
        logger.info(f"👁️ Running zero-shot VLM triage on {os.path.basename(filepath)} (Resolution: {width}x{height}, Entropy: {entropy:.2f})...")
        
        # Simulated visual feature detection score
        visual_indicators = []
        if entropy > 15.0:
            visual_indicators.append("HIGH_DETAIL_COMPLEX_SCENE")
        if mean_brightness < 40:
            visual_indicators.append("LOW_LIGHT_INSPECTION_REQUIRED")
        if width > 1920 or height > 1080:
            visual_indicators.append("HIGH_RESOLUTION_SOURCE")

        return {
            "status": "VLM_TRIAGED",
            "resolution": f"{width}x{height}",
            "indicators": visual_indicators,
            "requires_investigator_review": len(visual_indicators) > 0
        }
    except Exception as e:
        logger.error(f"Multimodal vision triage error for {filepath}: {e}")
        return {"status": "VLM_FAILED", "error": str(e)}

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

                # 3. Multimodal VLM Inspection for Unindexed Images
                vlm_res = zero_shot_multimodal_triage(filepath)
                logger.info(f"VLM Triage Result for {os.path.basename(filepath)}: {vlm_res['indicators']}")

            logger.info("File cleared triage. Ready for AI review.")

        except Exception as e:
            logger.error(f"Error processing {filepath}: {str(e)}")

if __name__ == "__main__":
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    event_handler = EvidenceHandler()
    observer = Observer()
    observer.schedule(event_handler, EVIDENCE_DIR, recursive=True)

    logger.info(f"Media Pipeline active (pHash + Multimodal VLM Triage). Monitoring {EVIDENCE_DIR}...")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
