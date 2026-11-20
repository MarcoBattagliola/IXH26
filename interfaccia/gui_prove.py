"""
Wrapper per la GUI: genera la prova con prove_image.prove() e stampa UNA riga JSON.
Uso: python gui_prove.py percorso/immagine.jpg
"""
import contextlib
import json
import subprocess
import sys
from pathlib import Path


def fail(msg, detail=""):
    print(json.dumps({"ok": False, "error": msg, "detail": detail[-3000:]}))
    sys.exit(1)


def main(path: str):
    try:
        # prove_image importa model.py: eventuali print finiscono su stderr, non nel JSON
        with contextlib.redirect_stdout(sys.stderr):
            from prove_image import BUILD, prove
            r = prove(path, quiet=True)
    except subprocess.CalledProcessError as e:
        err = (e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else str(e.stderr or "")
        fail(f"comando fallito: {' '.join(map(str, e.cmd[:2]))}", err)
    except FileNotFoundError as e:
        fail(f"file mancante: {e.filename} (avete eseguito setup_circuit?)")
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")

    data = json.load(open(r["calldata_path"]))
    thr = json.load(open(BUILD / "threshold.json"))
    print(json.dumps({
        "ok": True,
        **r,
        "is_ai": bool(r["is_ai"]),
        "score_fixed": data["instances"][-1],
        "threshold_fixed": thr["threshold_fixed"],
        "output_scale": thr["output_scale"],
        "threshold": thr["threshold_fixed"] / 2 ** thr["output_scale"],
    }))


if __name__ == "__main__":
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        fail("uso: python gui_prove.py immagine.jpg")
    main(sys.argv[1])
