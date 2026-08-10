import flwr as fl
import numpy as np
import logging
import os

logging.basicConfig(level=logging.INFO, format="[FLOWER CLIENT] %(asctime)s - %(message)s")
logger = logging.getLogger("FlowerClient")

class SentinelEdgeClient(fl.client.NumPyClient):
    """
    Local Edge Node Federated Learning Client.
    Simulates training local weights derived from edge evidence extraction
    and returns differentially private parameter updates to the central hub.
    """
    def __init__(self):
        # Simulated model weights (e.g. 5 feature layer matrices)
        self.weights = [np.random.randn(10, 10).astype(np.float32) for _ in range(5)]
        self.clipping_norm = 1.0
        self.noise_std = 0.01  # Gaussian Differential Privacy noise

    def get_parameters(self, config):
        return self.weights

    def fit(self, parameters, config):
        # 1. Receive updated global parameters from Central Hub
        self.weights = parameters

        # 2. Local Training Step (Simulated gradient update on local precinct evidence)
        logger.info("Executing local model update on precinct edge evidence...")
        for i in range(len(self.weights)):
            # Local update delta
            delta = np.random.normal(loc=0.0, scale=0.02, size=self.weights[i].shape).astype(np.float32)
            
            # Apply Differential Privacy Clipping
            norm = np.linalg.norm(delta)
            if norm > self.clipping_norm:
                delta = delta * (self.clipping_norm / norm)
            
            # Inject DP Noise
            dp_noise = np.random.normal(loc=0.0, scale=self.noise_std, size=delta.shape).astype(np.float32)
            
            self.weights[i] = self.weights[i] + delta + dp_noise

        num_examples = 100
        logger.info(f"Local training complete. Transmitting DP-protected weights ({num_examples} samples).")
        return self.weights, num_examples, {}

    def evaluate(self, parameters, config):
        self.weights = parameters
        loss = float(np.mean([np.std(w) for w in self.weights]))
        accuracy = 0.95
        logger.info(f"Evaluation complete. Loss: {loss:.4f}, Accuracy: {accuracy:.2f}")
        return loss, 100, {"accuracy": accuracy}

if __name__ == "__main__":
    hub_address = os.getenv("FLOWER_HUB_ADDRESS", "127.0.0.1:9092")
    logger.info(f"Connecting Sentinel Edge Client to Hub at {hub_address}...")
    
    root_certificates = None
    if os.path.exists("certs/ca.crt"):
        with open("certs/ca.crt", "rb") as f:
            root_certificates = f.read()
        logger.info("Loaded root CA certificate for mTLS gRPC connection.")

    try:
        if hasattr(fl.client, "start_numpy_client"):
            fl.client.start_numpy_client(
                server_address=hub_address, 
                client=SentinelEdgeClient(),
                root_certificates=root_certificates
            )
        else:
            fl.client.start_client(
                server_address=hub_address, 
                client=SentinelEdgeClient().to_client(),
                root_certificates=root_certificates
            )
    except Exception as e:
        logger.error(f"Client connection failed: {e}")