import merge from "deepmerge";
import rlp from "rlp";
import fs from "fs";
import path from "path";
import { encodeTransactionPayload, encodeTransactionEnvelope } from "@onflow/encode";
import {merkleIndex, merkleTree} from "../txMerkleTree.mjs";
import jsSHA from "jssha";

const TESTNET = "Testnet";
const MAINNET = "Mainnet";

const ADDRESS_TESTNET = "99a8ac2c71d4f6bd";
const ADDRESS_MAINNET = "f19c161bc24cf4b4";

const ADDRESSES = {
  [TESTNET]: ADDRESS_TESTNET,
  [MAINNET]: ADDRESS_MAINNET,
};

const encodeAccountKey = (publicKey, sigAlgo, hashAlgo, weight)  =>
  rlp
    .encode([
      Buffer.from(publicKey, "hex"),
      sigAlgo,
      hashAlgo,
      weight,
    ])
    .toString("hex")

const range = (start, end) => Array.from({length: end - start}, (v,k) => start + k);

const PUBLIC_KEY = "94488a795a07700c6fb83e066cf57dfd87f92ce70cbc81cb3bd3fea2df7b67073b70e36b44f3578b43d64d3faa2e8e415ef6c2b5fe4390d5a78e238581c6e4bc";

const SIG_ALGO_UNKNOWN = 0;
const SIG_ALGO_ECDSA_P256 = 2;
const SIG_ALGO_ECDSA_SECP256K1 = 3;
const SIG_ALGO_MAX = 255;

const SIG_ALGOS = [
  SIG_ALGO_UNKNOWN,
  SIG_ALGO_ECDSA_P256,
  SIG_ALGO_ECDSA_SECP256K1,
  SIG_ALGO_MAX,
];

const HASH_ALGO_UNKNOWN = 0;
const HASH_ALGO_SHA2_256 = 1;
const HASH_ALGO_SHA3_256 = 3;
const HASH_ALGO_MAX = 255;

const HASH_ALGOS = [
  HASH_ALGO_UNKNOWN,
  HASH_ALGO_SHA2_256,
  HASH_ALGO_SHA3_256,
  HASH_ALGO_MAX,
];

const WEIGHT_MIN = 0;
const WEIGHT_MID = 500;
const WEIGHT_MAX = 1000;

const WEIGHTS = [WEIGHT_MIN, WEIGHT_MID, WEIGHT_MAX];

const DEFAULT_ACCOUNT_KEY = encodeAccountKey(PUBLIC_KEY, SIG_ALGO_ECDSA_P256, HASH_ALGO_SHA3_256, WEIGHT_MAX);

const calculateHash = (msg) => {
  const shaObj = new jsSHA("SHA-256", "BYTES");
  shaObj.update(msg);
  return shaObj.getHash("HEX");
}

const getMerkleTreeElement = (idx) => merkleTree.children[idx[0]].children[idx[1]].children[idx[2]].children[idx[3]].children[0]

const combineMerge = (target, source, options) => {
  // empty list always overwrites target
  if (source.length == 0) return source

  const destination = target.slice()

  source.forEach((item, index) => {
    if (typeof destination[index] === "undefined") {
      destination[index] = options.cloneUnlessOtherwiseSpecified(item, options)
    } else if (options.isMergeableObject(item)) {
      destination[index] = merge(target[index], item, options)
    } else if (target.indexOf(item) === -1) {
      destination.push(item)
    }
  })

  return destination
};
  
const buildPayloadTx = (network, partialTx) =>
  merge(basePayloadTx(network), partialTx, {arrayMerge: combineMerge});

const buildEnvelopeTx = (network, partialTx) =>
  merge(baseEnvelopeTx(network), partialTx, {arrayMerge: combineMerge});

const basePayloadTx = (network) => {
  const address = ADDRESSES[network];

  return {
    script: "",
    arguments: [{ type: "String", value: DEFAULT_ACCOUNT_KEY }],
    refBlock: "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b",
    gasLimit: 42,
    proposalKey: {
      address: address,
      keyId: 4,
      sequenceNum: 10,
    },
    payer: address,
    authorizers: [address],
  };
};

const baseEnvelopeTx = (network) => {
  const address = ADDRESSES[network];

  return {
    ...basePayloadTx(network),
    payloadSigs: [
      {
        address: address,
        keyId: 4,
        sig: "f7225388c1d69d57e6251c9fda50cbbf9e05131e5adb81e5aa0422402f048162",
      },
    ],
  };
};

const createPayloadTestcase = (valid) => {
  return (x) => ({
    title: x[0],	
    valid: valid,	
    chainID: x[2],	
    payloadMessage: x[1],	
    envelopeMessage: { ...x[1], payloadSigs: [] },	
    encodedTransactionPayloadHex: encodeTransactionPayload(x[1]),	
    encodedTransactionEnvelopeHex: encodeTransactionEnvelope({ ...x[1], payloadSigs: [] }),
    metadata: getMerkleTreeElement(merkleIndex[x[3].substring(0, 16)]),
    hash: x[3],
  });
};

const createEnvelopeTestcase = (valid) => {
  return (x) => ({	
    title: x[0],	
    valid: valid,	
    chainID: x[2],	
    payloadMessage: x[1],	
    envelopeMessage: { ...x[1], payloadSigs: [] },	
    encodedTransactionPayloadHex: encodeTransactionPayload(x[1]),	
    encodedTransactionEnvelopeHex: encodeTransactionEnvelope({ ...x[1], payloadSigs: [] }),
    metadata: getMerkleTreeElement(merkleIndex[x[3].substring(0, 16)]),
    hash: x[3],
  });
};

const sampleArguments = (transactionArguments, sampleValuesCombination) => {
  return transactionArguments.map(({ type, sampleValues }, i) => {
    return sampleValues[sampleValuesCombination[i]];
  });
};

const numberOfRequiredTests = (args) => {
  return Math.max(1, ...args.map(({ type, sampleValues }) => sampleValues.length));
};

// Instead of taking all sampleValues combinations we just take (0, 0, ...), (1, 1, ..), ... .
// Last sampleValue is used if sampleValuesIdx is too high.
const selectArgumentCombinations = (transactionArguments) => {
  const maxSv = numberOfRequiredTests(transactionArguments);
  return range(0, maxSv).map((sampleValuesIdx) => 
    range(0, transactionArguments.length).map((i) => 
      Math.min(sampleValuesIdx, transactionArguments[i].sampleValues.length-1)
    )
  );
}

const testnetTemplates = JSON.parse(fs.readFileSync('../manifest.testnet.json')).templates;
const mainnetTemplates = JSON.parse(fs.readFileSync('../manifest.mainnet.json')).templates;


const manifestTestnetPayloadCases = testnetTemplates.flatMap((template) => {
  const combinations = selectArgumentCombinations(template.arguments);
  return combinations.map((combination, i) => [
    (combinations.length==1)?`${template.id} - ${template.name}`: 
                             `${template.id} - ${template.name} - ${i+1}`,
    buildPayloadTx(TESTNET, {
      script: template.source,
      arguments: sampleArguments(template.arguments || [], combination),
    }), 
    TESTNET, 
    calculateHash(template.source),
  ])
});

const manifestMainnetPayloadCases = mainnetTemplates.flatMap((template) => {
  const combinations = selectArgumentCombinations(template.arguments);
  return combinations.map((combination, i) => [
    (combinations.length==1)?`${template.id} - ${template.name}`: 
                             `${template.id} - ${template.name} - ${i+1}`,
    buildPayloadTx(MAINNET, {
      script: template.source,
      arguments: sampleArguments(template.arguments || [], combination),
    }),
    MAINNET,
    calculateHash(template.source),
  ])
});

const manifestTestnetEnvelopeCases = testnetTemplates.flatMap((template) => {
  const combinations = selectArgumentCombinations(template.arguments);
  return combinations.map((combination, i) => [
    (combinations.length==1)?`${template.id} - ${template.name}`: 
                             `${template.id} - ${template.name} - ${i+1}`,
    buildEnvelopeTx(TESTNET, {
      script: template.source,
      arguments: sampleArguments(template.arguments || [], combination),
    }),
    TESTNET,
    calculateHash(template.source),
  ])
});

const manifestMainnetEnvelopeCases = mainnetTemplates.flatMap((template) => {
  const combinations = selectArgumentCombinations(template.arguments);
  return combinations.map((combination, i) => [
    (combinations.length==1)?`${template.id} - ${template.name}`: 
                             `${template.id} - ${template.name} - ${i+1}`,
    buildEnvelopeTx(MAINNET, {
      script: template.source,
      arguments: sampleArguments(template.arguments || [], combination),
    }),
    MAINNET,
    calculateHash(template.source),
  ])
});

const manifestPayloadCases = [
  ...manifestTestnetPayloadCases,
  ...manifestMainnetPayloadCases,
].map(createPayloadTestcase(true));

const manifestEnvelopeCases = [
  ...manifestTestnetEnvelopeCases,
  ...manifestMainnetEnvelopeCases,
].map(createEnvelopeTestcase(true));


const args = process.argv.slice(2);
const outDir = args[0];

fs.writeFileSync(path.join(outDir, "manifestEnvelopeCases.json"), JSON.stringify(manifestEnvelopeCases, null, 2));
fs.writeFileSync(path.join(outDir, "manifestPayloadCases.json"), JSON.stringify(manifestPayloadCases, null, 2));
