// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Interfaccia del verifier Halo2 generato da `ezkl create-evm-verifier`.
/// Non è `view`: l'implementazione generata non lo dichiara.
interface IHalo2Verifier {
    function verifyProof(bytes calldata proof, uint256[] calldata instances) external returns (bool);
}

/// Registro dei risultati di testing verificati in zero-knowledge.
///
/// Legami garantiti:
///  - prova  <-> modello:  i pesi sono `fixed` nel circuito, quindi il contratto
///                         Verifier È il commitment al modello. Un Verifier = un modello.
///  - prova  <-> immagine: instances[0] è l'hash Poseidon dell'immagine preprocessata,
///                         calcolato DENTRO il circuito. Non si può più registrare
///                         un hash arbitrario con la prova di un'altra immagine.
///  - prova  <-> esito:    la soglia è applicata qui, sullo score dimostrato.
contract VerifiableTestingRegistry {
    // Modulo del campo scalare BN254: valori > R/2 codificano numeri negativi
    uint256 private constant BN254_R =
        21888242871839275222663642753224235399143128386484573929475034716133446086637;

    uint256 public constant IDX_IMAGE_HASH = 0;

    IHalo2Verifier public immutable verifier;
    uint256 public immutable numInstances;    // atteso: 2 (hash, score); controllatelo con prove_image.py
    uint256 public immutable thresholdFixed;  // round(THRESHOLD * 2^output_scale)
    uint256 public immutable outputScale;

    struct TestResult {
        bool exists;
        bool isAiGenerated;
        uint256 scoreFixed;
        uint64 timestamp;
        address submitter;
    }

    mapping(uint256 => TestResult) public results; // imageHash => risultato

    event TestVerified(uint256 indexed imageHash, bool isAiGenerated, uint256 scoreFixed, address indexed submitter);

    error WrongInstanceCount(uint256 got, uint256 expected);
    error AlreadyRegistered(uint256 imageHash);
    error NegativeScore();
    error InvalidProof();

    constructor(address verifier_, uint256 numInstances_, uint256 thresholdFixed_, uint256 outputScale_) {
        verifier = IHalo2Verifier(verifier_);
        numInstances = numInstances_;
        thresholdFixed = thresholdFixed_;
        outputScale = outputScale_;
    }

    function submitTestProof(bytes calldata proof, uint256[] calldata instances)
        external
        returns (bool isAi)
    {
        if (instances.length != numInstances) revert WrongInstanceCount(instances.length, numInstances);

        uint256 imageHash = instances[IDX_IMAGE_HASH];
        uint256 scoreFixed = instances[instances.length - 1]; // l'output è l'ultima instance
        if (results[imageHash].exists) revert AlreadyRegistered(imageHash);
        if (scoreFixed > BN254_R / 2) revert NegativeScore();

        // Il verifier generato può fare revert invece di restituire false: gestiamo entrambi
        if (!verifier.verifyProof(proof, instances)) revert InvalidProof();

        isAi = scoreFixed > thresholdFixed; // strettamente maggiore: score > soglia -> AI
        results[imageHash] = TestResult({
            exists: true,
            isAiGenerated: isAi,
            scoreFixed: scoreFixed,
            timestamp: uint64(block.timestamp),
            submitter: msg.sender
        });
        emit TestVerified(imageHash, isAi, scoreFixed, msg.sender);
    }
}
