"""
Training su CIFAKE (Kaggle: birdy654/cifake-real-and-ai-generated-synthetic-images).
Struttura dopo l'estrazione:
  cifake/train/REAL  cifake/train/FAKE  cifake/test/REAL  cifake/test/FAKE

ImageFolder ordina alfabeticamente: FAKE = 0, REAL = 1.
Noi vogliamo 1 = AI, quindi il target è 1 - etichetta.
"""
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torchvision import transforms
from torchvision.datasets import ImageFolder

from model import MiniCifakeCNN, PREPROCESS, IMG_SIZE

EPOCHS = 15
DATA = "cifake"

TRAIN_TF = transforms.Compose([
    transforms.RandomHorizontalFlip(),   # augmentation leggera, come nel repo originale
    PREPROCESS,
])


def to_ai_target(y):
    return (1 - y).float()


def main():
    train_ds = ImageFolder(f"{DATA}/train", transform=TRAIN_TF)
    test_ds = ImageFolder(f"{DATA}/test", transform=PREPROCESS)
    assert train_ds.class_to_idx == {"FAKE": 0, "REAL": 1}, train_ds.class_to_idx

    train_dl = DataLoader(train_ds, batch_size=128, shuffle=True, num_workers=2)
    test_dl = DataLoader(test_ds, batch_size=256, num_workers=2)

    model = MiniCifakeCNN()
    opt = torch.optim.Adam(model.parameters(), lr=3e-3)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, EPOCHS)
    loss_fn = nn.BCELoss()
    best = 0.0

    for epoch in range(EPOCHS):
        model.train()
        for x, y in train_dl:
            opt.zero_grad()
            loss_fn(model(x).squeeze(1), to_ai_target(y)).backward()
            opt.step()
        sched.step()

        model.eval()
        correct = total = 0
        with torch.no_grad():
            for x, y in test_dl:
                pred = (model(x).squeeze(1) > 0.5).float()
                correct += (pred == to_ai_target(y)).sum().item()
                total += y.numel()
        acc = correct / total
        print(f"epoch {epoch + 1}/{EPOCHS}  test accuracy {acc:.4f}")
        if acc > best:
            best = acc
            torch.save(model.state_dict(), "detector.pt")
    print(f"Migliore: {best:.4f} -> detector.pt")


if __name__ == "__main__":
    main()
