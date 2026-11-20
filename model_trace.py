"""
Classificatore a regola fissa: traccia della matrice dei grigi.

1. L'immagine viene ridotta a una matrice N x N (N = 32).
2. Ogni cella contiene la quantità di grigio del pixel, in [0, 1]:
   luminanza ITU-R BT.601  ->  Y = 0.299 R + 0.587 G + 0.114 B
   (0 = nero, 1 = bianco; con INVERT = True si usa 1 - Y, cioè 1 = nero).
3. Punteggio = somma degli elementi sulla diagonale (traccia), tra 0 e N.
4. Punteggio > 15  ->  generata da AI;  altrimenti  ->  reale.

Nel circuito ZK entra solo il punto 3 (moltiplicazione per una maschera
identità + somma): pochissimi vincoli, proving molto veloce.
La soglia NON è nel circuito: la applica lo smart contract.

Uso:
  python model.py export              -> detector.onnx
  python model.py classify img.jpg    -> stampa matrice, traccia e verdetto
"""
import json
import sys

import torch
import torch.nn as nn
from PIL import Image

N = 32            # lato della matrice: la traccia vale al massimo N
THRESHOLD = 15.0  # traccia > 15 -> AI
INVERT = False    # True: 1 = nero ("più grigio scuro" = valore più alto)


def gray_matrix(path: str) -> torch.Tensor:
    """Immagine -> matrice N x N di livelli di grigio in [0, 1], shape [1, 1, N, N]."""
    img = Image.open(path).convert("RGB").resize((N, N), Image.BILINEAR)
    rgb = torch.tensor(list(img.getdata()), dtype=torch.float32).view(N, N, 3) / 255.0
    y = 0.299 * rgb[..., 0] + 0.587 * rgb[..., 1] + 0.114 * rgb[..., 2]
    if INVERT:
        y = 1.0 - y
    return y.view(1, 1, N, N)


class DiagonalTraceClassifier(nn.Module):
    """Restituisce la traccia della matrice dei grigi (il punteggio)."""

    def __init__(self):
        super().__init__()
        # Maschera identità: tiene solo gli elementi della diagonale
        self.register_buffer("diag_mask", torch.eye(N).view(1, 1, N, N))

    def forward(self, x):
        return (x * self.diag_mask).sum(dim=(2, 3))  # shape [1, 1]


def classify(path: str) -> tuple[float, bool]:
    x = gray_matrix(path)
    score = DiagonalTraceClassifier()(x).item()
    return score, score > THRESHOLD


# Stessi nomi usati da prove_image.py e setup_circuit.sh
def load_image_tensor(path: str) -> torch.Tensor:
    return gray_matrix(path)


def write_ezkl_input(tensor: torch.Tensor, out_path: str) -> None:
    flat = tensor.detach().reshape(-1).tolist()
    with open(out_path, "w") as f:
        json.dump({"input_data": [flat]}, f)


def export_onnx(onnx_path: str = "detector.onnx") -> None:
    model = DiagonalTraceClassifier().eval()
    dummy = torch.rand(1, 1, N, N)
    kwargs = dict(input_names=["gray_matrix"], output_names=["trace"],
                  opset_version=13, do_constant_folding=True)
    try:
        torch.onnx.export(model, dummy, onnx_path, dynamo=False, **kwargs)
    except TypeError:
        torch.onnx.export(model, dummy, onnx_path, **kwargs)
    print(f"Esportato {onnx_path}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "export"
    if cmd == "export":
        export_onnx()
    elif cmd == "classify":
        for p in sys.argv[2:]:
            m = gray_matrix(p).view(N, N)
            diag = torch.diagonal(m)
            score, is_ai = classify(p)
            print(f"\n{p}")
            print("  diagonale:", " ".join(f"{v:.2f}" for v in diag.tolist()))
            print(f"  traccia = {score:.3f}  (soglia {THRESHOLD}, max {N})")
            print(f"  verdetto: {'GENERATA DA AI' if is_ai else 'REALE'}")
    else:
        print(__doc__)
