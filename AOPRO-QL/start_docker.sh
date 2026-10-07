#!/bin/bash
# Start script for AOPRO-QL Docker environment

set -e

AOPRO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AOPRO_CONTAINER="${AOPRO_DOCKER_CONTAINER:-aopro-ql-container}"

echo "Setting up AOPRO-QL Docker environment..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    exit 1
fi

# Build the image
echo "Building AOPRO-QL image..."
docker build -t aopro-ql:latest "$AOPRO_DIR"

# Check if container already exists
if docker container inspect "$AOPRO_CONTAINER" > /dev/null 2>&1; then
    echo "Container '$AOPRO_CONTAINER' already exists"
    # Start it if it's stopped
    docker start "$AOPRO_CONTAINER"
else
    # Create and run new container
    echo "Creating new container '$AOPRO_CONTAINER'..."
    docker run -d \
        --name "$AOPRO_CONTAINER" \
        -v "$AOPRO_DIR":/workspace \
        -v "$AOPRO_DIR/juliet-test-suite-c":/workspace/juliet-test-suite-c \
        aopro-ql:latest \
        tail -f /dev/null
fi

echo ""
echo "AOPRO-QL Docker environment is ready!"
echo "Container name: $AOPRO_CONTAINER"
echo ""
echo "You can now run AOPRO-QL commands:"
echo "  python3 run_juliet.py --cwe 190"
echo ""
echo "Or enter the container:"
echo "  docker exec -it $AOPRO_CONTAINER bash"
