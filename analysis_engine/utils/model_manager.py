import os
import logging
from transformers import AutoTokenizer, AutoModelForCausalLM
from huggingface_hub import snapshot_download

logger = logging.getLogger(__name__)

BASE_MODEL_NAME = "Qwen/Qwen2.5-1.5B"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_ROOT_DIR = os.path.join(BASE_DIR, "models")
BASE_MODEL_DIR = os.path.join(MODELS_ROOT_DIR, "qwen2.5-1.5b")
ADAPTER_DIR = os.path.join(MODELS_ROOT_DIR, "qwen2.5-1.5b-adapter")  # your fine-tuned adapter path


def ensure_model_downloaded():
    """
    Ensures base model and adapter exist in PWD/models/
    Downloads base model if missing.
    Adapter is expected to be provided by user.
    """

    os.makedirs(MODELS_ROOT_DIR, exist_ok=True)

    # -------------------------------
    # 1. Check Base Model
    # -------------------------------
    if not os.path.exists(BASE_MODEL_DIR):
        logger.info("Base model not found. Downloading Qwen2.5-1.5B...")
        download_base_model()
    else:
        logger.info("Base model already exists. Skipping download.")

    # -------------------------------
    # 2. Check Adapter
    # -------------------------------
    if not os.path.exists(ADAPTER_DIR):
        logger.warning(
            f"Adapter folder NOT found at {ADAPTER_DIR}.\n"
            "⚠️ Please place your fine-tuned adapter here before running LLM analysis."
        )
    else:
        logger.info("LoRA adapter found.")


def download_base_model():
    """
    Download Qwen2.5-1.5B safely for low-VRAM systems.
    """
    try:
        snapshot_download(
            repo_id=BASE_MODEL_NAME,
            local_dir=BASE_MODEL_DIR,
            local_dir_use_symlinks=False,
            ignore_patterns=[
                "*.msgpack",
                "*.h5",
                "*.ot",
                "*.bin"  # avoid duplicate weights
            ]
        )
        logger.info("Qwen2.5-1.5B downloaded successfully.")

    except Exception as e:
        logger.error(f"Failed to download base model: {e}")
        raise


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    try:
        ensure_model_downloaded()
    except Exception:
        logger.exception("An error occurred while ensuring the model was downloaded.")
        raise
