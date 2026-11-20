"""
FASE DI TESTING VERIFICABILE.

1. Valuta il modello float su tutto il test set CIFAKE (accuracy + matrice di confusione).
2. Estrae un campione di K immagini (seed fisso, riproducibile), genera una prova
   EZKL per ciascuna e confronta il punteggio ZK quantizzato con quello float.
3. Scrive build/testing_report.json: le prove del campione si inviano on-chain
   con submit.py, così chiunque può verificare quei risultati di test.

Uso: python evaluate_zk.py [K=20]
"""
import json
import random
import sys
from pathlib import Path

import torch
from PIL import Image
from torch.utils.data import DataLoader
from torchvision.datasets import ImageFolder

from model import PREPROCESS, THRESHOLD, load_model
from prove_image import prove

DATA = "cifake/test"
K = int(sys.argv[1]) if len(sys.argv) > 1 else 20
SEED = 2026


def main():
    model = load_model()
    ds = ImageFolder(DATA, transform=PREPROCESS)  # FAKE = 0, REAL = 1

    # 1) testing classico in float
    tp = tn = fp = fn = 0
    with torch.no_grad():
        for x, y in DataLoader(ds, batch_size=512):
            pred_ai = model(x).squeeze(1) > THRESHOLD
            true_ai = y == 0
            tp += (pred_ai & true_ai).sum().item()
            tn += (~pred_ai & ~true_ai).sum().item()
            fp += (pred_ai & ~true_ai).sum().item()
            fn += (~pred_ai & true_ai).sum().item()
    acc = (tp + tn) / (tp + tn + fp + fn)
    print(f"Accuracy float: {acc:.4f}")
    print(f"              pred AI   pred REALE")
    print(f"  vero AI     {tp:7d}   {fn:9d}")
    print(f"  vero REALE  {fp:7d}   {tn:9d}")

    # 2) campione con prove ZK
    random.seed(SEED)
    sample = random.sample(ds.samples, K)
    rows, agree = [], 0
    for i, (path, label) in enumerate(sample, 1):
        with torch.no_grad():
            f_score = model(PREPROCESS(Image.open(path).convert("RGB")).unsqueeze(0)).item()
        r = prove(path, quiet=True)
        same = (f_score > THRESHOLD) == r["is_ai"]
        agree += same
        rows.append({"image": path, "true_ai": label == 0, "float_score": round(f_score, 4),
                     "zk_score": round(r["zk_score"], 4), "zk_is_ai": bool(r["is_ai"]),
                     "decisions_agree": bool(same), "image_hash": r["image_hash"],
                     "calldata": r["calldata_path"]})
        print(f"[{i}/{K}] float {f_score:.3f}  zk {r['zk_score']:.3f}  "
              f"{'OK' if same else 'DIVERSO (effetto quantizzazione)'}  {Path(path).name}")

    report = {"float_accuracy": acc, "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
              "zk_sample_size": K, "seed": SEED, "zk_float_agreement": agree / K, "samples": rows}
    json.dump(report, open("build/testing_report.json", "w"), indent=2)
    print(f"\nAccordo float/ZK sul campione: {agree}/{K}. Report: build/testing_report.json")


if __name__ == "__main__":
    main()
