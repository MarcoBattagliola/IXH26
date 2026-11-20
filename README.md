# IXH26 – Rilevatore reale vs AI con testing verificabile in ZK

Ispirato a KeiraJames/Real-vs-AI-Image-Detector (architettura CNN + dataset CIFAKE),
riscritto in PyTorch e ridotto per EZKL. Codice e pesi del repo originale NON sono
riutilizzati (nessuna licenza indicata nel repo: vedi regole slide 22).

## Flusso
1. `pip install -r requirements.txt`
2. Scaricate CIFAKE da Kaggle in `cifake/` (controllate la licenza del dataset)
3. `python train.py` -> `detector.pt`
4. `./setup_circuit.sh cifake/test/FAKE/<una_immagine>.jpg`
   -> `contracts/Verifier.sol`, chiavi, `build/threshold.json`
5. `python evaluate_zk.py 20` -> accuracy, matrice di confusione, 20 prove ZK,
   `build/testing_report.json`
6. Deploy (Foundry; es. sidechain EVM di XRPL):
   ```
   forge create contracts/Verifier.sol:Halo2Verifier --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
   forge create contracts/VerifiableTestingRegistry.sol:VerifiableTestingRegistry \
     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast \
     --constructor-args <VERIFIER_ADDR> <NUM_INSTANCES> <THRESHOLD_FIXED> <OUTPUT_SCALE>
   ```
7. `python submit.py build/<immagine>/calldata.json` per ogni campione

`model_trace.py`: la versione a regola fissa (traccia della matrice dei grigi > 15).

## Note
- Verifier.sol troppo grande (>24 KB)? Optimizer di solc o "reusable verifier" di EZKL.
- Il sistema dimostra che il modello certificato ha dato quel punteggio su quell'immagine,
  non che l'immagine sia autentica.
- Dichiarazione AI obbligatoria (slide 23): codice generato/corretto con Claude (Anthropic).
