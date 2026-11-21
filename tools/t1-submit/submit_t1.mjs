#!/usr/bin/env node
// XRPL submitter for Hackaton2026 (Node + xrpl.js). The Go code only READS
// from XRPL; everything that signs and submits a transaction lives here.
//
// Usage:
//   node submit_t1.mjs <D-hex>              T1: publish the 32-byte capture commitment
//   node submit_t1.mjs --memo <TYPE> <hex> [<hex> ...]
//                                           one transaction, one memo per payload
//                                           (e.g. CA registry events)
//   node submit_t1.mjs --probe-memo <TYPE> <hex>
//                                           like --memo but submit WITHOUT waiting and
//                                           print {"engine_result"}: used to show that
//                                           an under-signed transaction is refused
//   node submit_t1.mjs --setup-governance   turn XRPL_SEED's account into a 2-of-3
//                                           multisign account and DISABLE its master key;
//                                           prints {"account","signers":[seed,seed,seed]}
//   node submit_t1.mjs --fund               testnet/devnet: funded throwaway account,
//                                           prints {"address","seed"}
//   node submit_t1.mjs --whoami             print {"address"} of XRPL_SEED (offline)
//
// Env:
//   XRPL_WSS            WebSocket endpoint (default: testnet wss://s.altnet.rippletest.net:51233)
//   XRPL_SEED           seed of the sending account (single-signature mode). If unset
//                       for T1 on testnet/devnet, a throwaway account is funded.
//   XRPL_ACCOUNT        sending account address (multisign mode; default: from XRPL_SEED)
//   XRPL_SIGNER_SEEDS   comma-separated signer seeds: if set, the transaction is
//                       MULTI-signed by these signers instead of XRPL_SEED.
// Stdout: one JSON object (diagnostics go to stderr).
import { Client, Wallet, convertStringToHex, multisign } from "xrpl";

const T1_MEMO_TYPE = "HACKATON2026_T1"; // must match capture.T1MemoType
const QUORUM = 2;
const SIGNERS = 3;
const asfDisableMaster = 4;

const out = (o) => console.log(JSON.stringify(o));
const fail = (msg, code = 2) => {
  console.error(msg);
  process.exit(code);
};
const isHex = (p) => /^([0-9a-fA-F]{2})+$/.test(p);
const memo = (type, hex) => ({ Memo: { MemoType: convertStringToHex(type), MemoData: hex.toUpperCase() } });

const [mode = "", ...rest] = process.argv.slice(2);
const signerSeeds = (process.env.XRPL_SIGNER_SEEDS || "").split(",").map((s) => s.trim()).filter(Boolean);

if (mode === "--whoami") {
  if (!process.env.XRPL_SEED) fail("--whoami needs XRPL_SEED");
  out({ address: Wallet.fromSeed(process.env.XRPL_SEED).address });
  process.exit(0);
}

// Parse arguments before connecting.
let memos;
if (mode === "--memo" || mode === "--probe-memo") {
  const [type, ...payloads] = rest;
  if (!type || payloads.length === 0 || !payloads.every(isHex)) fail(`usage: node submit_t1.mjs ${mode} <TYPE> <hex> [<hex> ...]`);
  memos = payloads.map((p) => memo(type, p));
} else if (mode !== "--fund" && mode !== "--setup-governance") {
  if (!/^[0-9a-fA-F]{64}$/.test(mode)) fail("usage: node submit_t1.mjs <64-hex-char commitment>  (see header for other modes)");
  memos = [memo(T1_MEMO_TYPE, mode)];
}

const url = process.env.XRPL_WSS || "wss://s.altnet.rippletest.net:51233";
const client = new Client(url);

// Single-signature or multisign, depending on XRPL_SIGNER_SEEDS.
async function signedBlob(tx) {
  if (signerSeeds.length > 0) {
    const prepared = await client.autofill(tx, signerSeeds.length);
    return multisign(signerSeeds.map((s) => Wallet.fromSeed(s).sign(prepared, true).tx_blob));
  }
  const wallet = Wallet.fromSeed(process.env.XRPL_SEED);
  return wallet.sign(await client.autofill(tx)).tx_blob;
}

async function submitAndCheck(blob) {
  const r = (await client.submitAndWait(blob)).result;
  const result = typeof r.meta === "object" ? r.meta.TransactionResult : undefined;
  if (!r.validated || result !== "tesSUCCESS") {
    throw new Error(`transaction not successful: validated=${r.validated} result=${result}`);
  }
  return r;
}

function sender() {
  if (process.env.XRPL_ACCOUNT) return process.env.XRPL_ACCOUNT;
  if (process.env.XRPL_SEED) return Wallet.fromSeed(process.env.XRPL_SEED).address;
  return undefined;
}

try {
  await client.connect();

  if (mode === "--fund") {
    const { wallet } = await client.fundWallet();
    out({ address: wallet.address, seed: wallet.seed });
  } else if (mode === "--setup-governance") {
    if (!process.env.XRPL_SEED) fail("--setup-governance needs XRPL_SEED (the funded governance account)");
    const master = Wallet.fromSeed(process.env.XRPL_SEED);
    const signers = Array.from({ length: SIGNERS }, () => Wallet.generate());
    // Signer addresses do not need to be funded accounts.
    await submitAndCheck(master.sign(await client.autofill({
      TransactionType: "SignerListSet",
      Account: master.address,
      SignerQuorum: QUORUM,
      SignerEntries: signers.map((w) => ({ SignerEntry: { Account: w.address, SignerWeight: 1 } })),
    })).tx_blob);
    // Without this, the master key could still sign alone and the multisign would be pointless.
    const r = await submitAndCheck(master.sign(await client.autofill({
      TransactionType: "AccountSet", Account: master.address, SetFlag: asfDisableMaster,
    })).tx_blob);
    console.error(`governance ${master.address}: ${QUORUM}-of-${SIGNERS} multisign, master key disabled`);
    out({ account: master.address, signers: signers.map((w) => w.seed), ledger_index: r.ledger_index });
  } else {
    let account = sender();
    if (!account) {
      if (mode !== "--memo" && mode !== "--probe-memo") {
        console.error(`XRPL_SEED not set: funding a throwaway account from the faucet of ${url} ...`);
        const { wallet } = await client.fundWallet();
        process.env.XRPL_SEED = wallet.seed;
        account = wallet.address;
        console.error(`funded ${account} (testnet only; set XRPL_SEED to reuse an account)`);
      } else {
        fail("set XRPL_SEED or XRPL_ACCOUNT + XRPL_SIGNER_SEEDS");
      }
    }
    const blob = await signedBlob({ TransactionType: "AccountSet", Account: account, Memos: memos });
    if (mode === "--probe-memo") {
      const r = (await client.submit(blob)).result;
      out({ engine_result: r.engine_result });
    } else {
      const r = await submitAndCheck(blob);
      out({ hash: r.hash, ledger_index: r.ledger_index });
    }
  }
} catch (err) {
  console.error(`XRPL submission failed: ${err?.message ?? err}`);
  process.exitCode = 1;
} finally {
  if (client.isConnected()) await client.disconnect();
}
