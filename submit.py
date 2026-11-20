"""
Invia una prova al registry on-chain.
Variabili d'ambiente: RPC_URL, PRIVATE_KEY, REGISTRY_ADDRESS
Uso: python submit.py build/<nome_immagine>/calldata.json

ATTENZIONE: la PRIVATE_KEY va solo in una variabile d'ambiente locale,
mai nel codice, nel repo o condivisa con i mentor (slide 39).
"""
import json
import os
import sys

from web3 import Web3

ABI = [{
    "name": "submitTestProof", "type": "function", "stateMutability": "nonpayable",
    "inputs": [{"name": "proof", "type": "bytes"}, {"name": "instances", "type": "uint256[]"}],
    "outputs": [{"name": "isAi", "type": "bool"}],
}]


def main(path: str):
    data = json.load(open(path))
    proof = bytes.fromhex(data["proof"][2:])
    instances = [int(v) for v in data["instances"]]

    w3 = Web3(Web3.HTTPProvider(os.environ["RPC_URL"]))
    acct = w3.eth.account.from_key(os.environ["PRIVATE_KEY"])
    registry = w3.eth.contract(address=Web3.to_checksum_address(os.environ["REGISTRY_ADDRESS"]), abi=ABI)

    # Simulazione prima dell'invio: se la prova è invalida vedete l'errore senza pagare gas
    is_ai = registry.functions.submitTestProof(proof, instances).call({"from": acct.address})
    print(f"Simulazione OK, isAi = {is_ai}")

    tx = registry.functions.submitTestProof(proof, instances).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": w3.eth.chain_id,
    })
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    rcpt = w3.eth.wait_for_transaction_receipt(h)
    print(f"tx {h.hex()}  status={rcpt.status}  gas={rcpt.gasUsed}")


if __name__ == "__main__":
    main(sys.argv[1])
