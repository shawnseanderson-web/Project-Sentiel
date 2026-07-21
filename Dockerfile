# Stage 1: Build Environment
FROM alpine:latest AS builder

# Install build dependencies for llama.cpp, OpenBLAS, and Vulkan
RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    openblas-dev \
    vulkan-loader \
    vulkan-headers \
    vulkan-tools \
    linux-headers

# Clone the llama.cpp repository
RUN git clone https://github.com/ggerganov/llama.cpp.git /usr/src/llama.cpp

WORKDIR /usr/src/llama.cpp

# Compile with OpenBLAS and Vulkan support
RUN cmake -B build \
    -DGGML_BLAS=ON \
    -DGGML_BLAS_VENDOR=OpenBLAS \
    -DGGML_VULKAN=ON \
    && cmake --build build --config Release -j $(nproc)

# Stage 2: Minimal Runtime Environment
FROM alpine:latest

# Install runtime dependencies only
RUN apk add --no-cache \
    openblas \
    vulkan-loader \
    libstdc++

# Copy compiled binaries from the builder stage
COPY --from=builder /usr/src/llama.cpp/build/bin/ /usr/local/bin/

# Create a non-root user for CJIS compliance (Security Matrix 4.2)
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
USER sentinel

# Define the immutable, read-only evidence directory mount point
VOLUME [ "/evidence" ]

# Set the entrypoint to the local inference server
ENTRYPOINT ["llama-server"]