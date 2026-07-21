import flwr as fl

# Define the Federated Averaging (FedAvg) strategy
strategy = fl.server.strategy.FedAvg(
    fraction_fit=1.0,           # Sample 100% of available connected nodes for training
    min_fit_clients=2,          # Wait for at least 2 precincts to connect before training
    min_available_clients=2,    # Minimum number of active nodes required
)

if __name__ == "__main__":
    print("🚀 Starting Sentinel Federated Learning Hub...")
    # Start Flower server for continuous federated learning rounds
    fl.server.start_server(
        server_address="0.0.0.0:9092",
        config=fl.server.ServerConfig(num_rounds=10),
        strategy=strategy,
    )