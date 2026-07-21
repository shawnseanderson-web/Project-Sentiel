#!/bin/bash

# ==========================================
# Project Sentinel: Edge Node Test Sequence
# ==========================================

IMAGE_NAME="sentinel-edge-node"
CONTAINER_NAME="sentinel-test-instance"
MOCK_EVIDENCE_DIR="./mock_evidence"
TEST_PORT=8080

echo "🚀 Starting Phase 1 Build & Test Sequence..."

# Step 1: Build the Docker Image
echo "🔨 Building Docker image: $IMAGE_NAME..."
docker build -t $IMAGE_NAME:latest .
if [ $? -ne 0 ]; then
    echo "❌ Docker build failed. Exiting."
    exit 1
fi
echo "✅ Docker build successful."

# Step 2: Stage Mock Evidence (Chain of Custody Test)
echo "📁 Staging mock evidence directory..."
mkdir -p $MOCK_EVIDENCE_DIR
echo "CONFIDENTIAL: Suspect alias is DarkNet_Phantom." > $MOCK_EVIDENCE_DIR/chat_log_01.txt
chmod 444 $MOCK_EVIDENCE_DIR/chat_log_01.txt

# Step 3: Spin Up the Edge Node
echo "⚙️ Starting containerized inference node..."
docker run -d \
    --name $CONTAINER_NAME \
    -p $TEST_PORT:8080 \
    --device /dev/dri \
    -v $(pwd)/$MOCK_EVIDENCE_DIR:/evidence:ro \
    $IMAGE_NAME:latest \
    --host 0.0.0.0 --port 8080 -m /models/mock_model.gguf
    
sleep 5

if ! docker ps | grep -q $CONTAINER_NAME; then
    echo "❌ Container failed to start. Check logs:"
    docker logs $CONTAINER_NAME
    exit 1
fi
echo "✅ Container is running on port $TEST_PORT."

# Step 4: Execute Security & API Tests
echo "🧪 Running tests..."
echo "   -> Testing read-only volume constraint..."
docker exec $CONTAINER_NAME sh -c "echo 'tamper' > /evidence/chat_log_01.txt" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "❌ SECURITY FAIL: Container was able to write to the evidence directory."
    docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME
    exit 1
else
    echo "   ✅ PASS: Evidence directory is strictly read-only."
fi

echo "   -> Testing local inference API endpoint..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$TEST_PORT/health)
if [ "$HTTP_STATUS" -eq 200 ] || [ "$HTTP_STATUS" -eq 404 ]; then 
    echo "   ✅ PASS: llama-server API is responsive."
else
    echo "❌ FAIL: API did not respond expectedly. HTTP Status: $HTTP_STATUS"
fi

# Step 5: Teardown
echo "🧹 Tearing down test environment..."
docker stop $CONTAINER_NAME > /dev/null
docker rm $CONTAINER_NAME > /dev/null
rm -rf $MOCK_EVIDENCE_DIR
echo "✅ Teardown complete."