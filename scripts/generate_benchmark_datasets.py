#!/usr/bin/env python3
"""
Benchmark Dataset Generator for llm-firewall-rs
================================================
Generates domain-stratified datasets to drive quantitative F1 threshold analysis
for the guardian-core entropy detector.

Produces:
  - tests/fixtures/dataset_standard.json     (~10k items)
  - tests/fixtures/dataset_crypto.json       (~10k items)
  - tests/fixtures/dataset_healthcare.json   (~10k items)
  - tests/fixtures/threshold_sweep_results.json  (optimal thresholds per domain)

Usage:
  python3 scripts/generate_benchmark_datasets.py
"""

import json
import math
import random
import string
import base64
import hashlib
import os

random.seed(42)  # Reproducible

# ---------------------------------------------------------------------------
# Shannon entropy (mirrors the Rust EntropyDetector byte-level implementation)
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[int, int] = {}
    for b in s.encode("latin-1", errors="replace"):
        freq[b] = freq.get(b, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# True-Positive generators: real secret formats that MUST be caught
# (Modified to avoid GitHub Push Protection blocking fake AKIA/ghp_ tokens)
# ---------------------------------------------------------------------------

def gen_fake_api_key() -> str:
    # High entropy token, generic
    suffix = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    return f"random_key_{suffix}"

def gen_fake_client_secret() -> str:
    # High entropy token
    tail = "".join(random.choices(string.ascii_letters + string.digits + "_-", k=40))
    return f"sec_{tail}"

def gen_fake_oauth_token() -> str:
    body = "".join(random.choices(string.ascii_letters + string.digits, k=40))
    return f"oauth_{body}"

def gen_high_entropy_password() -> str:
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choices(charset, k=random.randint(24, 40)))

def gen_base64_secret() -> str:
    raw_bytes = bytes(random.choices(range(256), k=random.randint(24, 48)))
    return base64.b64encode(raw_bytes).decode()

def gen_hex_secret() -> str:
    return "".join(random.choices("0123456789abcdef", k=random.randint(32, 64)))


# ---------------------------------------------------------------------------
# Domain-specific False-Positive generators (must NOT be flagged)
# ---------------------------------------------------------------------------

def gen_ethereum_address() -> str:
    """0x + 40 hex chars — high entropy but NOT a secret."""
    body = "".join(random.choices("0123456789abcdefABCDEF", k=40))
    return f"0x{body}"


def gen_solana_pubkey() -> str:
    """Base58, 44 chars — statistically high entropy."""
    b58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return "".join(random.choices(b58_chars, k=44))


def gen_tx_hash() -> str:
    """SHA-256 style 64-char hex transaction hash."""
    return hashlib.sha256(random.randbytes(32)).hexdigest()


def gen_block_hash() -> str:
    """Ethereum-style 0x + 64 hex block hash."""
    body = "".join(random.choices("0123456789abcdef", k=64))
    return f"0x{body}"


def gen_contract_address() -> str:
    """Ethereum contract address."""
    body = "".join(random.choices("0123456789abcdefABCDEF", k=40))
    return f"0x{body}"


def gen_fhir_uuid() -> str:
    """UUID used as FHIR resource IDs — not a secret."""
    parts = [
        "".join(random.choices("0123456789abcdef", k=8)),
        "".join(random.choices("0123456789abcdef", k=4)),
        "4" + "".join(random.choices("0123456789abcdef", k=3)),
        random.choice("89ab") + "".join(random.choices("0123456789abcdef", k=3)),
        "".join(random.choices("0123456789abcdef", k=12)),
    ]
    return "-".join(parts)


def gen_dicom_uid() -> str:
    """DICOM UID — long numeric with dots, not a secret."""
    root = "1.2.840.10008"
    suffix = ".".join(str(random.randint(1, 99999)) for _ in range(4))
    return f"{root}.{suffix}"


def gen_hl7_message_id() -> str:
    """HL7 MSH message control ID — alphanumeric, not a secret."""
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=20))


def gen_patient_ref() -> str:
    """FHIR Reference like Patient/12345 — not a secret."""
    pid = "".join(random.choices(string.digits, k=8))
    return f"Patient/{pid}"


# ---------------------------------------------------------------------------
# Context wrappers
# ---------------------------------------------------------------------------

_TP_CONTEXTS = [
    "export SECRET_KEY={}",
    "authorization header: {}",
    'const apiSecret = "{}";',
    "# hardcoded for now: {}",
    'credentials = "{}"',
    "token: {}",
    "// TODO remove before PR: {}",
    "PRIVATE_KEY={}",
    "password={}",
    'auth_token = "{}"',
    "api_key: {}",
    "secret: {}",
]

_FP_CRYPTO_CONTEXTS = [
    "sending to address: {}",
    "from address: {}",
    "tx hash: {}",
    "block hash: {}",
    "contract deployed at: {}",
    "wallet: {}",
    "recipient: {}",
    "validator pubkey: {}",
    "program id: {}",
    "mint authority: {}",
]

_FP_HEALTHCARE_CONTEXTS = [
    "Patient resource ID: {}",
    "FHIR reference: {}",
    "DICOM UID: {}",
    "HL7 message ID: {}",
    "encounter ID: {}",
    "observation resource: {}",
    "specimen ID: {}",
    "claim reference: {}",
]

_FP_STANDARD_CONTEXTS = [
    "build SHA: {}",
    "git commit: {}",
    "content-md5: {}",
    "etag: {}",
    "session id: {}",
    "idempotency key: {}",
    "trace id: {}",
    "request id: {}",
]


def wrap(template: str, value: str) -> str:
    return template.format(value)


# ---------------------------------------------------------------------------
# Item builders
# ---------------------------------------------------------------------------

def make_tp_item(item_id: str, domain: str, gen_fn, context_template: str) -> dict:
    value = gen_fn()
    text = wrap(context_template, value)
    start = text.find(value)
    return {
        "id": item_id,
        "domain": domain,
        "is_secret": True,
        "text": text,
        "secret_value": value,
        "entropy": round(shannon_entropy(value), 6),
        "span": {"start": start, "end": start + len(value)} if start >= 0 else None,
    }


def make_fp_item(item_id: str, domain: str, gen_fn, context_template: str) -> dict:
    value = gen_fn()
    text = wrap(context_template, value)
    return {
        "id": item_id,
        "domain": domain,
        "is_secret": False,
        "text": text,
        "secret_value": value,
        "entropy": round(shannon_entropy(value), 6),
        "span": None,
    }


# ---------------------------------------------------------------------------
# Domain dataset builders
# ---------------------------------------------------------------------------

def build_standard_dataset(n: int = 10_000) -> list:
    items = []
    half = n // 2

    tp_gens = [gen_fake_api_key, gen_fake_client_secret, gen_fake_oauth_token, gen_high_entropy_password,
               gen_base64_secret, gen_hex_secret]
    fp_gens = [
        lambda: hashlib.md5(random.randbytes(16)).hexdigest(),
        lambda: hashlib.sha1(random.randbytes(20)).hexdigest(),
        lambda: str(random.randint(1_000_000, 9_999_999)),
        lambda: "".join(random.choices(string.ascii_lowercase, k=random.randint(12, 20))),
    ]

    for i in range(half):
        gen = tp_gens[i % len(tp_gens)]
        ctx = _TP_CONTEXTS[i % len(_TP_CONTEXTS)]
        items.append(make_tp_item(f"STD-TP-{i:05d}", "standard", gen, ctx))

    for i in range(n - half):
        gen = fp_gens[i % len(fp_gens)]
        ctx = _FP_STANDARD_CONTEXTS[i % len(_FP_STANDARD_CONTEXTS)]
        items.append(make_fp_item(f"STD-FP-{i:05d}", "standard", gen, ctx))

    random.shuffle(items)
    return items


def build_crypto_dataset(n: int = 10_000) -> list:
    items = []
    half = n // 2

    tp_gens = [gen_fake_api_key, gen_fake_client_secret, gen_high_entropy_password, gen_base64_secret,
               gen_hex_secret, gen_fake_oauth_token]
    fp_gens = [gen_ethereum_address, gen_solana_pubkey, gen_tx_hash,
               gen_block_hash, gen_contract_address]

    for i in range(half):
        gen = tp_gens[i % len(tp_gens)]
        ctx = _TP_CONTEXTS[i % len(_TP_CONTEXTS)]
        items.append(make_tp_item(f"CRYPTO-TP-{i:05d}", "crypto", gen, ctx))

    for i in range(n - half):
        gen = fp_gens[i % len(fp_gens)]
        ctx = _FP_CRYPTO_CONTEXTS[i % len(_FP_CRYPTO_CONTEXTS)]
        items.append(make_fp_item(f"CRYPTO-FP-{i:05d}", "crypto", gen, ctx))

    random.shuffle(items)
    return items


def build_healthcare_dataset(n: int = 10_000) -> list:
    items = []
    half = n // 2

    tp_gens = [gen_fake_api_key, gen_fake_client_secret, gen_high_entropy_password, gen_base64_secret,
               gen_hex_secret, gen_fake_oauth_token]
    fp_gens = [gen_fhir_uuid, gen_dicom_uid, gen_hl7_message_id, gen_patient_ref]

    for i in range(half):
        gen = tp_gens[i % len(tp_gens)]
        ctx = _TP_CONTEXTS[i % len(_TP_CONTEXTS)]
        items.append(make_tp_item(f"HEALTH-TP-{i:05d}", "healthcare", gen, ctx))

    for i in range(n - half):
        gen = fp_gens[i % len(fp_gens)]
        ctx = _FP_HEALTHCARE_CONTEXTS[i % len(_FP_HEALTHCARE_CONTEXTS)]
        items.append(make_fp_item(f"HEALTH-FP-{i:05d}", "healthcare", gen, ctx))

    random.shuffle(items)
    return items


# ---------------------------------------------------------------------------
# F1-sweep analysis: find optimal threshold per domain
# ---------------------------------------------------------------------------

def f1_sweep(items: list, threshold_steps: int = 200) -> list:
    """
    Iterate entropy threshold from 0.0 to 8.0 bits (200 steps = 0.04 bit resolution).
    The Rust EntropyDetector uses raw Shannon bits (default 4.1).
    Classifier: predicted_secret = item.entropy >= threshold.
    """
    results = []
    for step in range(threshold_steps + 1):
        threshold = (step / threshold_steps) * 8.0
        tp = fp = fn = 0
        for item in items:
            predicted = item["entropy"] >= threshold
            actual = item["is_secret"]
            if predicted and actual:
                tp += 1
            elif predicted and not actual:
                fp += 1
            elif not predicted and actual:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        results.append({
            "threshold": round(threshold, 4),
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        })
    return results


def find_optimal(sweep_results: list) -> dict:
    return max(sweep_results, key=lambda r: r["f1"])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(script_dir, "..", "crates", "guardian-core", "tests", "fixtures")
    os.makedirs(out_dir, exist_ok=True)

    print("Generating datasets (seed=42, reproducible)...")

    datasets = {
        "standard": build_standard_dataset(10_000),
        "crypto": build_crypto_dataset(10_000),
        "healthcare": build_healthcare_dataset(10_000),
    }

    for name, data in datasets.items():
        path = os.path.join(out_dir, f"dataset_{name}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  Wrote {len(data):,} items → {os.path.basename(path)}")

    print("\nRunning F1 threshold sweeps (200 steps, 0.04-bit resolution)...")
    summary = {}
    for name, data in datasets.items():
        sweep = f1_sweep(data)
        optimal = find_optimal(sweep)
        summary[name] = {
            "optimal_entropy_threshold_bits": optimal["threshold"],
            "f1_at_optimal": optimal["f1"],
            "precision_at_optimal": optimal["precision"],
            "recall_at_optimal": optimal["recall"],
            "dataset_size": len(data),
            "tp_count": sum(1 for i in data if i["is_secret"]),
            "fp_count": sum(1 for i in data if not i["is_secret"]),
            "sweep": sweep,
        }
        print(
            f"  [{name:12s}] optimal={optimal['threshold']:.4f} bits  "
            f"F1={optimal['f1']:.4f}  P={optimal['precision']:.4f}  R={optimal['recall']:.4f}"
        )

    sweep_path = os.path.join(out_dir, "threshold_sweep_results.json")
    with open(sweep_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nFull sweep results → {os.path.basename(sweep_path)}")

    # Print thresholds in a format ready to paste into domain.rs
    print("\n" + "=" * 65)
    print("QUANTITATIVELY DERIVED THRESHOLDS (paste into domain.rs)")
    print("=" * 65)
    for name, result in summary.items():
        print(
            f"  {name:12s}: entropy_tier = {result['optimal_entropy_threshold_bits']:.4f}  "
            f"(F1={result['f1_at_optimal']:.4f})"
        )
    print("=" * 65)
    print()
    print("These are raw Shannon bits on the 0–8 scale.")
    print("They match the Rust EntropyDetector.threshold field (default: 4.1 bits).")


if __name__ == "__main__":
    main()
