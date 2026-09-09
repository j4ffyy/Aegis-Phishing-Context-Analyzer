# Aegis Backend — Docker Build Configuration
#
# Bakes the DistilBERT ONNX model and tokenizer into the image at BUILD
# time to eliminate runtime downloads and cold-start latency on Render.com.
#
# Memory target: < 150MB RSS (no PyTorch — ONNX Runtime only)
# Platform: linux/amd64 (Render.com free tier)

FROM python:3.11-slim

WORKDIR /app

# 1. Install Python dependencies (CPU-only, no torch)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Bake DistilBERT ONNX model and tokenizer into the image at build time.
#    This runs download_model.py during docker build so the model is
#    available on the filesystem from the first request — no runtime download.
COPY scripts/download_model.py scripts/
RUN python scripts/download_model.py

# 3. Copy application source code and seed data
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
