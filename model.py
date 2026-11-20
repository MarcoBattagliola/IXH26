"""
Rilevatore reale vs AI per EZKL, ispirato al CNN di KeiraJames/Real-vs-AI-Image-Detector
(stessa idea: blocchi conv -> pooling -> denso -> sigmoide, stesso dataset CIFAKE),
ma riscritto in PyTorch e ridotto per stare in un circuito ZK.

Differenze rispetto al modello originale (Keras):
  originale: input 256x256, conv 16/32/64 + BatchNorm + MaxPool, Dense 512
             -> ~29,5 milioni di parametri (quasi tutti nel Dense 57.600 x 512)
  questo:    input 32x32 (risoluzione nativa di CIFAKE), conv 8/16 con stride,
             AvgPool, niente BatchNorm/Dropout -> ~1.600 parametri, ~130k moltiplicazioni

CONVENZIONE ETICHETTE: output vicino a 1 = generata da AI.
(Nel repo originale è il contrario: < 0.5 = AI.)

Uso:
  python model.py export            -> detector.onnx (richiede detector.pt)
  python model.py classify img.jpg  -> punteggio e verdetto in float
"""
import json
import sys

import torch
import torch.nn as nn
from PIL import Image
from torchvision import transforms

IMG_SIZE = 32
THRESHOLD = 0.5   # score > THRESHOLD -> AI (applicata dallo smart contract)

PREPROCESS = transforms.Compose([
    transforms.Resize((IMG_SIZE, IMG_SIZE)),
    transforms.ToTensor(),  # [0, 1], nessuna normalizzazione: meno costanti nel circuito
])


class MiniCifakeCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(3, 8, 3, stride=2, padding=1),   # 32 -> 16
            nn.ReLU(),
            nn.Conv2d(8, 16, 3, stride=2, padding=1),  # 16 -> 8
            nn.ReLU(),
            nn.AvgPool2d(2),                           # 8 -> 4
            nn.Flatten(),                              # 16*4*4 = 256
            nn.Linear(256, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x)


def load_image_tensor(path: str) -> torch.Tensor:
    return PREPROCESS(Image.open(path).convert("RGB")).unsqueeze(0)


def write_ezkl_input(tensor: torch.Tensor, out_path: str) -> None:
    with open(out_path, "w") as f:
        json.dump({"input_data": [tensor.detach().reshape(-1).tolist()]}, f)


def load_model(weights_path: str = "detector.pt") -> MiniCifakeCNN:
    model = MiniCifakeCNN()
    model.load_state_dict(torch.load(weights_path, map_location="cpu"))
    return model.eval()


def export_onnx(weights_path: str = "detector.pt", onnx_path: str = "detector.onnx") -> None:
    model = load_model(weights_path)
    dummy = torch.rand(1, 3, IMG_SIZE, IMG_SIZE)
    kwargs = dict(input_names=["image"], output_names=["score"],
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
        m = load_model()
        with torch.no_grad():
            for p in sys.argv[2:]:
                s = m(load_image_tensor(p)).item()
                print(f"{p}: score {s:.3f} -> {'AI' if s > THRESHOLD else 'REALE'}")
