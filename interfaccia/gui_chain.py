"""
Wrapper on-chain per la GUI. Stampa UNA riga JSON.
  python gui_chain.py submit build/<id>/calldata.json   -> simula e invia submitTestProof
  python gui_chain.py lookup 0x<image_hash>              -> legge results(imageHash)
  python gui_chain.py info                               -> parametri del registry
Variabili d'ambiente: RPC_URL, REGISTRY_ADDRESS (+ PRIVATE_KEY solo per submit).
La chiave privata viene letta solo dall'ambiente e non viene mai stampata.
"""
import json
import os
import sys

ABI = [
    {"name": "submitTestProof", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "proof", "type": "bytes"}, {"name": "instances", "type": "uint256[]"}],
     "outputs": [{"name": "isAi", "type": "bool"}]},
    {"name": "results", "type": "function", "stateMutability": "view",
     "inputs": [{"name": "", "type": "uint256"}],
     "outputs": [{"name": "exists", "type": "bool"}, {"name": "isAiGenerated", "type": "bool"},
                 {"name": "scoreFixed", "type": "uint256"}, {"name": "timestamp", "type": "uint64"},
                 {"name": "submitter", "type": "address"}]},
    *[{"name": n, "type": "function", "stateMutability": "view", "inputs": [],
       "outputs": [{"name": "", "type": t}]}
      for n, t in (("verifier", "address"), ("numInstances", "uint256"),
                   ("thresholdFixed", "uint256"), ("outputScale", "uint256"))],
]


def out(**kw):
    print(json.dumps(kw, default=str))


def need(*names):
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        out(ok=False, error="variabili d'ambiente mancanti: " + ", ".join(missing))
        sys.exit(1)


def registry():
    from web3 import Web3  # import qui: errori su env mancanti arrivano prima
    w3 = Web3(Web3.HTTPProvider(os.environ["RPC_URL"]))
    c = w3.eth.contract(address=Web3.to_checksum_address(os.environ["REGISTRY_ADDRESS"]), abi=ABI)
    return w3, c


def revert_reason(e):
    msg = str(e)
    for name in ("WrongInstanceCount", "AlreadyRegistered", "NegativeScore", "InvalidProof"):
        if name in msg:
            return name
    return msg[:500]


def submit(path):
    need("RPC_URL", "REGISTRY_ADDRESS", "PRIVATE_KEY")
    data = json.load(open(path))
    proof = bytes.fromhex(data["proof"][2:])
    instances = [int(v) for v in data["instances"]]
    w3, reg = registry()
    acct = w3.eth.account.from_key(os.environ["PRIVATE_KEY"])

    try:
        is_ai = reg.functions.submitTestProof(proof, instances).call({"from": acct.address})
    except Exception as e:  # noqa: BLE001  (revert in simulazione: nessun gas speso)
        out(ok=False, stage="simulazione", error=revert_reason(e))
        return

    tx = reg.functions.submitTestProof(proof, instances).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": w3.eth.chain_id,
    })
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    rcpt = w3.eth.wait_for_transaction_receipt(h, timeout=180)
    out(ok=rcpt.status == 1, is_ai=bool(is_ai), tx_hash="0x" + h.hex().removeprefix("0x"),
        status=rcpt.status, gas_used=rcpt.gasUsed, block=rcpt.blockNumber,
        submitter=acct.address, chain_id=w3.eth.chain_id)


def lookup(image_hash):
    need("RPC_URL", "REGISTRY_ADDRESS")
    _, reg = registry()
    exists, is_ai, score, ts, who = reg.functions.results(int(image_hash, 16)).call()
    scale = reg.functions.outputScale().call()
    out(ok=True, exists=exists, is_ai=is_ai, score_fixed=str(score),
        score=score / 2 ** scale if exists else None, timestamp=ts, submitter=who)


def info():
    need("RPC_URL", "REGISTRY_ADDRESS")
    w3, reg = registry()
    f = reg.functions
    out(ok=True, chain_id=w3.eth.chain_id, registry=reg.address, verifier=f.verifier().call(),
        num_instances=f.numInstances().call(), threshold_fixed=str(f.thresholdFixed().call()),
        output_scale=f.outputScale().call())


if __name__ == "__main__":
    try:
        cmd = sys.argv[1]
        if cmd == "submit":
            submit(sys.argv[2])
        elif cmd == "lookup":
            lookup(sys.argv[2])
        elif cmd == "info":
            info()
        else:
            raise IndexError
    except IndexError:
        out(ok=False, error="uso: gui_chain.py submit <calldata.json> | lookup <0xhash> | info")
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        out(ok=False, error=f"{type(e).__name__}: {str(e)[:500]}")
        sys.exit(1)
