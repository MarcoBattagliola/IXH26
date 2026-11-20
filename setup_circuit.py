import os
import sys
import json
import asyncio
import inspect

import ezkl

from model import THRESHOLD, load_image_tensor, write_ezkl_input, export_onnx

# Percorsi
ONNX = "detector.onnx"
CALIB = "build/calib.json"
SETTINGS = "build/settings.json"
COMPILED = "build/model.compiled"
VK = "build/vk.key"
PK = "build/pk.key"
SOL = "contracts/Verifier.sol"
ABI = "build/Verifier.abi"
THRESHOLD_JSON = "build/threshold.json"


async def run_step(name, function, *args, **kwargs):
    """Esegue una funzione (sincrona o asincrona) e controlla il risultato."""
    print(f"\n=== {name} ===", flush=True)

    result = function(*args, **kwargs)

    if inspect.isawaitable(result):
        result = await result

    if result is False:
        raise RuntimeError(f"EZKL ha restituito False durante: {name}")

    print(f"Completato: {name}", flush=True)
    return result


async def main():
    if len(sys.argv) < 2:
        raise SystemExit(
            "Uso: python setup_circuit.py percorso/immagine_calibrazione.jpg"
        )

    image_path = sys.argv[1]

    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Immagine non trovata: {image_path}")

    os.makedirs("build", exist_ok=True)
    os.makedirs("contracts", exist_ok=True)

    # 1. Esporta il modello PyTorch in ONNX
    await run_step("Esportazione ONNX", export_onnx)

    # 2. Prepara il dato di calibrazione
    tensor = load_image_tensor(image_path)
    write_ezkl_input(tensor, CALIB)

    # 3. Genera le impostazioni EZKL
    args = ezkl.PyRunArgs()
    args.input_visibility = "hashed"
    args.param_visibility = "fixed"
    args.output_visibility = "public"

    await run_step(
        "Generazione settings",
        ezkl.gen_settings,
        ONNX,
        SETTINGS,
        py_run_args=args,
    )

    # 4. Calibrazione
    await run_step(
        "Calibrazione",
        ezkl.calibrate_settings,
        CALIB,
        ONNX,
        SETTINGS,
        "resources",
    )

    # 5. Compilazione circuito
    await run_step(
        "Compilazione circuito",
        ezkl.compile_circuit,
        ONNX,
        COMPILED,
        SETTINGS,
    )

    # 6. SRS
    await run_step("Generazione/recupero SRS", ezkl.get_srs, SETTINGS)

    # 7. Chiavi di proving e verifica
    await run_step("Setup chiavi", ezkl.setup, COMPILED, VK, PK)

    # 8. Generazione smart contract Solidity e ABI
    await run_step(
        "Generazione Verifier Solidity",
        ezkl.create_evm_verifier,
        VK,
        SETTINGS,
        SOL,
        ABI,
    )

    # 9. Calcola la soglia in virgola fissa
    with open(SETTINGS) as f:
        settings = json.load(f)

    scale = settings["model_output_scales"][0]
    threshold_fixed = round(THRESHOLD * (2 ** scale))

    with open(THRESHOLD_JSON, "w") as f:
        json.dump(
            {
                "output_scale": scale,
                "threshold_fixed": threshold_fixed,
            },
            f,
            indent=2,
        )

    print("\n===================================")
    print("       SETUP COMPLETATO!")
    print("===================================")
    print(f"Output scale: {scale}")
    print(f"Threshold fixed: {threshold_fixed}")
    print(f"Verifier: {SOL}")
    print(f"ABI: {ABI}")
    print(f"Proving key: {PK}")
    print(f"Verification key: {VK}")


if __name__ == "__main__":
    asyncio.run(main())