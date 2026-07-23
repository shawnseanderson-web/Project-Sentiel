# Stage 1: Build Environment
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install prerequisites for adding external repositories
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    ca-certificates \
    build-essential \
    pkg-config \
    cmake \
    git \
    libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

# Add the official LunarG Signing Key and Vulkan Repository for Ubuntu 22.04 (Jammy)
RUN wget -qO- https://packages.lunarg.com/lunarg-signing-key-pub.asc | tee /etc/apt/trusted.gpg.d/lunarg.asc \
    && wget -qO /etc/apt/sources.list.d/lunarg-vulkan-jammy.list http://packages.lunarg.com/vulkan/lunarg-vulkan-jammy.list

# Install the LunarG Vulkan SDK (which includes shaderc, headers, and glslc)
RUN apt-get update && apt-get install -y --no-install-recommends \
    vulkan-sdk \
    && rm -rf /var/lib/apt/lists/*

# Clone the llama.cpp repository
RUN git clone https://github.com/ggml-org/llama.cpp.git /usr/src/llama.cpp

WORKDIR /usr/src/llama.cpp

# Compile with OpenBLAS and Vulkan support
RUN cmake -B build \
    -DGGML_BLAS=ON \
    -DGGML_BLAS_VENDOR=OpenBLAS \
    -DGGML_VULKAN=ON \
    && cmake --build build --config Release -j $(nproc)

# Gather all shared libraries into a staging directory so they can be copied to Stage 2
RUN mkdir -p /staging/lib && find /usr/src/llama.cpp/build -name "*.so" -exec cp {} /staging/lib/ \;

# Stage 2: Minimal Runtime Environment
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libopenblas0 \
    libvulkan1 \
    libstdc++6 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binaries from the builder stage
COPY --from=builder /usr/src/llama.cpp/build/bin/ /usr/local/bin/

# Copy the staged shared libraries from the builder stage and register them
COPY --from=builder /staging/lib/ /usr/local/lib/
RUN ldconfig

# Create a non-root user for CJIS compliance
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel
USER sentinel

# Define the immutable, read-only evidence directory mount point
VOLUME [ "/evidence" ]

# Set the entrypoint to the local inference server
ENTRYPOINT ["llama-server"]