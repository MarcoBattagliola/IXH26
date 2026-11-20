"""
Genera la prova ZK per una o più immagini e prepara i parametri per il contratto.
Uso: python prove_image.py img1.jpg [img2.jpg ...]
Output: build/<nome>/calldata.json (proof + instances)
"""
import json
import subprocess
import sys
from pathlib import Path

from eth_abi import decode

from model import load_image_tensor, write_ezkl_input

BUILD = Path("build")
BN254_R = 21888242871839275222663642753224235399143128386484573929475034716133446086637


def run(*args, quiet=False):
    if not quiet:
        print("$", " ".join(args))
    subprocess.run(args, check=True, capture_output=quiet)


def prove(image_path: str, quiet: bool = False) -> dict:
    out = BUILD / Path(image_path).stem
    out.mkdir(parents=True, exist_ok=True)
    write_ezkl_input(load_image_tensor(image_path), str(out / "input.json"))

    model, pk, vk, settings = (str(BUILD / f) for f in ("model.compiled", "pk.key", "vk.key", "settings.json"))
    run("ezkl", "gen-witness", "-D", str(out / "input.json"), "-M", model, "-O", str(out / "witness.json"), quiet=quiet)
    run("ezkl", "prove", "--witness", str(out / "witness.json"), "-M", model,
        "--pk-path", pk, "--proof-path", str(out / "proof.json"), quiet=quiet)
    run("ezkl", "verify", "--proof-path", str(out / "proof.json"),
        "--settings-path", settings, "--vk-path", vk, quiet=quiet)
    run("ezkl", "encode-evm-calldata", "--proof-path", str(out / "proof.json"),
        "--calldata-path", str(out / "calldata.bin"), quiet=quiet)

    # Decodifica della calldata di verifyProof(bytes,uint256[]): instances
    # nello stesso ordine e codifica che il Verifier si aspetta.
    raw = (out / "calldata.bin").read_bytes()
    if raw[:2] in (b"0x", b"0X"):
        raw = bytes.fromhex(raw[2:].decode().strip())
    proof_bytes, instances = decode(["bytes", "uint256[]"], raw[4:])

    thr = json.load(open(BUILD / "threshold.json"))
    scale = thr["output_scale"]
    image_hash, score_fixed = instances[0], instances[-1]   # ordine EZKL: input hash ... output
    signed = score_fixed - BN254_R if score_fixed > BN254_R // 2 else score_fixed
    zk_score = signed / 2 ** scale
    is_ai = score_fixed > thr["threshold_fixed"]

    if not quiet:
        print(f"\n{image_path}: {len(instances)} instances")
        print(f"  image hash Poseidon = {hex(image_hash)}")
        print(f"  score ZK = {zk_score:.4f} -> AI: {is_ai}")

    result = {"proof": "0x" + proof_bytes.hex(), "instances": [str(v) for v in instances]}
    json.dump(result, open(out / "calldata.json", "w"), indent=2)
    return {"calldata_path": str(out / "calldata.json"), "zk_score": zk_score,
            "is_ai": is_ai, "image_hash": hex(image_hash), "n_instances": len(instances)}


if __name__ == "__main__":
    for p in sys.argv[1:]:
        prove(p)
