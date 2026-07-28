import os
from huggingface_hub import hf_hub_download

# Configuration for the Edge Inference Node Model
# (Targeting a high-efficiency quantized instruction model optimized for edge hardware)
REPO_ID = "Qwen/Qwen2.5-7B-Instruct-GGUF"
FILENAME = "qwen2.5-7b-instruct-q4_k_m.gguf"
LOCAL_DIR = "./models"

def download_edge_model():
    """
    Downloads the specified GGUF model from Hugging Face and places it 
    directly into the local models directory for Docker container mounting.
    """
    os.makedirs(LOCAL_DIR, exist_ok=True)
    print(f"Initializing secure download for [{FILENAME}] from repo [{REPO_ID}]...")
    
    try:
        downloaded_path = hf_hub_download(
            repo_id=REPO_ID,
            filename=FILENAME,
            local_dir=LOCAL_DIR,
            local_dir_use_symlinks=False
        )
        print(f"Download complete. Model successfully staged at: {downloaded_path}")
    except Exception as e:
        print(f"Error downloading model: {str(e)}")

if __name__ == "__main__":
    download_edge_model()