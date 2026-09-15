FROM python:3.11-slim

WORKDIR /app

# Install dependencies required to build liboqs
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    ninja-build \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs 0.16.0
RUN git clone --branch 0.16.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
    -G Ninja \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /tmp/liboqs/build && \
    cmake --install /tmp/liboqs/build && \
    rm -rf /tmp/liboqs

# Update the dynamic linker cache
RUN ldconfig

# Install Python dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

RUN mkdir -p uploads

EXPOSE 8080

CMD ["python", "app.py"]