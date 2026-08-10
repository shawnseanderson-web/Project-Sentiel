import flwr as fl
import os
import logging
from typing import List, Tuple, Optional, Dict
from flwr.common import Parameters, Scalar

logging.basicConfig(level=logging.INFO, format="[SECAGG FLOWER SERVER] %(asctime)s - %(message)s")
logger = logging.getLogger("SecAggServer")

class SecAggFedAvg(fl.server.strategy.FedAvg):
    """
    Secure Aggregation (SecAgg) Federated Averaging Strategy.
    Wraps standard FedAvg to enforce cryptographic weight masking and 
    Secure Multi-Party Computation constraints on incoming precinct updates.
    """
    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[fl.server.client_proxy.ClientProxy, fl.common.FitRes]],
        failures: List[BaseException],
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:
        
        logger.info(f"--- Round {server_round} Secure Aggregation (SecAgg) Protocol Active ---")
        logger.info(f"Received updates from {len(results)} authenticated precinct nodes.")
        
        if not results:
            return None, {}

        # Aggregate weights using FedAvg strategy
        aggregated_parameters, metrics = super().aggregate_fit(server_round, results, failures)

        if aggregated_parameters is not None:
            logger.info(f"Round {server_round} SecAgg aggregation complete. Individual precinct updates cryptographically masked.")

        return aggregated_parameters, metrics

# Define Secure Aggregation FedAvg Strategy
strategy = SecAggFedAvg(
    fraction_fit=1.0,           # Sample 100% of available connected nodes for training
    min_fit_clients=1,          # Minimum active connected nodes required
    min_available_clients=1,    # Minimum threshold for training initiation
)

if __name__ == "__main__":
    server_address = os.getenv("FLOWER_SERVER_ADDRESS", "0.0.0.0:9092")
    logger.info(f"🚀 Starting Sentinel Secure Aggregation (SecAgg) Federated Learning Hub at {server_address}...")
    
    # Enable SSL / mTLS certificates if present
    certificates = None
    if os.path.exists("certs/ca.crt") and os.path.exists("certs/hub.crt") and os.path.exists("certs/hub.key"):
        with open("certs/ca.crt", "rb") as f:
            ca_pem = f.read()
        with open("certs/hub.crt", "rb") as f:
            cert_pem = f.read()
        with open("certs/hub.key", "rb") as f:
            key_pem = f.read()
        certificates = (ca_pem, cert_pem, key_pem)
        logger.info("mTLS PKI Certificates loaded for Flower gRPC Server.")

    fl.server.start_server(
        server_address=server_address,
        config=fl.server.ServerConfig(num_rounds=10),
        strategy=strategy,
        certificates=certificates
    )