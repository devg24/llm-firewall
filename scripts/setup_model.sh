#!/bin/bash
set -euo pipefail

trap 'rm -f "${MODEL_DIR:-./model}"/*.tmp.$$' EXIT

# 1. Check for curl
if ! command -v curl &> /dev/null; then
    echo "Error: curl is required but not installed." >&2
    exit 1
fi

# 2. Determine MODEL_DIR
MODEL_DIR="${MODEL_DIR:-./model}"
echo "Setting up model assets in directory: ${MODEL_DIR}"

# 3. Create directory
mkdir -p "${MODEL_DIR}"

# Idempotency check: if all files exist and have non-zero size, exit early.
if [ -s "${MODEL_DIR}/config.json" ] && [ -s "${MODEL_DIR}/tokenizer.json" ] && [ -s "${MODEL_DIR}/model.safetensors" ]; then
    echo "Model files already exist and are not empty. Skipping download."
    exit 0
fi

# 4. Download config.json
if [ ! -s "${MODEL_DIR}/config.json" ]; then
    echo "Downloading config.json..."
    curl --max-time 300 -L --fail -o "${MODEL_DIR}/config.json.tmp.$$" "https://huggingface.co/dslim/bert-base-NER/resolve/main/config.json"
    mv "${MODEL_DIR}/config.json.tmp.$$" "${MODEL_DIR}/config.json"
fi

# 5. Download tokenizer.json
if [ ! -s "${MODEL_DIR}/tokenizer.json" ]; then
    echo "Downloading tokenizer.json..."
    curl --max-time 300 -L --fail -o "${MODEL_DIR}/tokenizer.json.tmp.$$" "https://huggingface.co/dslim/bert-base-NER/resolve/main/tokenizer.json"
    mv "${MODEL_DIR}/tokenizer.json.tmp.$$" "${MODEL_DIR}/tokenizer.json"
fi

# 6. Download model.safetensors
if [ ! -s "${MODEL_DIR}/model.safetensors" ]; then
    echo "Downloading model.safetensors..."
    curl --max-time 300 -L --fail -o "${MODEL_DIR}/model.safetensors.tmp.$$" "https://huggingface.co/dslim/bert-base-NER/resolve/main/model.safetensors"
    mv "${MODEL_DIR}/model.safetensors.tmp.$$" "${MODEL_DIR}/model.safetensors"
fi

# 7. Check that all files exist and are not empty
for file in config.json tokenizer.json model.safetensors; do
    if [ ! -s "${MODEL_DIR}/${file}" ]; then
        echo "Error: File ${file} is empty or missing." >&2
        exit 1
    fi
done

echo "Successfully downloaded all model assets to ${MODEL_DIR}!"
