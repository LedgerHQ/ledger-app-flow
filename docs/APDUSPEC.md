# Flow App

## General structure

The general structure of commands and responses is as follows:

### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0x33 |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

### Return codes

| Return code | Description             |
| ----------- | ----------------------- |
| 0x6400      | Execution Error         |
| 0x6700      | Wrong length            |
| 0x6982      | Empty buffer            |
| 0x6983      | Output buffer too small |
| 0x6984      | Data invalid            |
| 0x6985      | Conditions not stisfied |
| 0x6986      | Command not allowed     |
| 0x6987      | Tx not initialized      |
| 0x6A80      | Bad key handle          |
| 0x6B00      | Invalid P1 - P2         |
| 0x6D00      | INS not supported       |
| 0x6E00      | CLA not supported       |
| 0x6F00      | Unknown                 |
| 0x6F01      | Sign verify error       |
| 0x9000      | Success                 |
| 0x9001      | Busy                    |

---

## Derivation Paths

Flow supports a range of signature schemes and hash algorithms.

In order to keep these public keys separated, the second items in the derivation path is used to indicate the signature scheme to use.

| Field   | Type     | Content              | Expected    |
| ------- | -------- | -------------------- | ----------- |
| Path[0] | byte (4) | Derivation Path Data | 44'         |
| Path[1] | byte (4) | Derivation Path Data | 539'        |
| Path[2] | byte (4) | Derivation Path Data | ?           |
| Path[3] | byte (4) | Derivation Path Data | ?           |
| Path[4] | byte (4) | Derivation Path Data | ?           |

Path hardening in item3 and item4 is optional. In case the device contains app version <= 0.9.12 two least significant bytes of Path[2] contain cryptooptions, but the codes of P-256 and secp256k1 curves are reversed.

## Crypto options

Crypto options are stored as 16-bit integer, more significant byte stores curve, less significant byte stores hash.

### Signatures

| Algorithm | Curve     | ID              | Code |
| --------- | --------- | --------------- | ---- |
| ECDSA     | P-256     | ECDSA_P256      | 2    |
| ECDSA     | secp256k1 | ECDSA_secp256k1 | 3    |

### Hashes

| Algorithm | Output Size | ID       | Code |
| --------- | ----------- | -------- | ---- |
| SHA-2     | 256         | SHA2_256 | 1    |
| SHA-3     | 256         | SHA3_256 | 3    |

---

## Account Slots

Account information can be temporarily stored in the device slots.
Each account slot contains an account identifier and the corresponding derivation path.
Only a 1:1 account/path relation can be stored per slot.

Each slot has the following structure

| Field   | Type    |                       |
| ------- | ------- | --------------------- |
| Account | byte(8) | Account Identifier    |
| Path    | u32 (5) | Derivation Path       |
| Options | byte(2) | Crypto options (LE)   |

---

## Commands definition

### GET_VERSION

Returns the App version.

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x33     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                            |
| ------- | -------- | ---------------- | ------------------------------- |
| TEST    | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR   | byte (1) | Version Major    |                                 |
| MINOR   | byte (1) | Version Minor    |                                 |
| PATCH   | byte (1) | Version Patch    |                                 |
| LOCKED  | byte (1) | Device is locked |                                 |
| DEV_ID  | byte (4) | Device_ID        | see values in each sdk          |
| SW1-SW2 | byte (2) | Return code      | see list of return codes        |

---

### INS_GET_PUBKEY

Returns the public key.

#### Command

| Field   | Type     | Content                   | Expected           |
| ------- | -------- | ------------------------- | ------------------ |
| CLA     | byte (1) | Application Identifier    | 0x33               |
| INS     | byte (1) | Instruction ID            | 0x01               |
| P1      | byte (1) | Request User confirmation | No = 0             |
| P2      | byte (1) | Parameter 2               | ignored            |
| L       | byte (1) | Bytes in payload          | (depends)          |
| Path[0] | byte (4) | Derivation Path Data      | 0x80000000 \| 44   |
| Path[1] | byte (4) | Derivation Path Data      | 0x80000000 \| 539' |
| Path[2] | byte (4) | Derivation Path Data      | ?                  |
| Path[3] | byte (4) | Derivation Path Data      | ?                  |
| Path[4] | byte (4) | Derivation Path Data      | ?                  |
| Options | byte (2) | CryptoOptions (LE)        | ?                  |

#### Response

| Field    | Type        | Content     | Note           |
| -------- | ----------- | ----------- | -------------- |
| PK       | byte (65)   | Public Key  | binary encoded |
| PK-ASCII | byte (65x2) | Public key  | ascii encoded  |

### INS_SIGN

Signs a transaction. The payload contains the transaction, split according to the size limit, and possibly metadata with their Merkle tree proof.

#### Command

| Field | Type     | Content                | Expected           |
| ----- | -------- | ---------------------- | ------------------ |
| CLA   | byte (1) | Application Identifier | 0x33               |
| INS   | byte (1) | Instruction ID         | 0x02               |
| P1    | byte (1) | Payload desc           | 0 = init           |
|       |          |                        | 1 = add            |
|       |          |                        | 2 = final          |
|       |          |                        | 3 = metadata       |
|       |          |                        | 4 = MT proof       |
|       |          |                        | 5 = MT proof final |
|       |          |                        | 10 = message final |
| P2    | byte (1) | Parameter 2            | ignored            |
| L     | byte (1) | Bytes in payload       | (depends)          |

We use the gollowing types of payloads. Detailed descriptions of datafollows later:
- 0 = init: Initializes signing. Clears all buffers. Contains derivation path and crypto options.
- 1 = add: Appends chunk of a transaction/message
- 2 = final: Appends chunk of a transaction. Starts transaction signing without metadata.
- 3 = metadata: Transaction signing metadata (Like transaction name, script hash, e.t.c). Resets Merkle tree proof.
- 4 = MT proof: One Merkle tree proof step
- 5 = MT proof final: Final Merkle tree proof step. Starts transaction signing with metadata.
- 10 = message final: Appends chunk of a message. Starts message signing.

There are three workflows now consisting of the following packets. 
- Sign transaction with metadata: 1 init packet, 1-* add packets, 1 metadata packet, 4 MT proof packets, 1 MT proof final packet.
- Sign transaction without metadata: 1 init packet, 0-* add packets, 1 final packet.
- Sign message: 1 init packet, 0-* add packets, 1 message final packet.
The app does not enforce the exact order of the packets. Packets final and message final try so sign current tx/message. Packet 5 = MT proof final tries to sign current tx provided that the Merkle tree proof is correctly finished.

##### Init Packet P1 = 0x00

| Field   | Type     | Content              | Expected |
| ------- | -------- | -------------------- | -------- |
| Path[0] | byte (4) | Derivation Path Data | 44'      |
| Path[1] | byte (4) | Derivation Path Data | 539'     |
| Path[2] | byte (4) | Derivation Path Data | ?        |
| Path[3] | byte (4) | Derivation Path Data | ?        |
| Path[4] | byte (4) | Derivation Path Data | ?        |
| Options | byte (2) | Crypto options (LE)  | ?        |

This clears data and sets detivation path and crypto options variable.

##### Add Packet P1 = 0x01

| Field   | Type    | Content                  | Expected |
| ------- | ------- | ------------------------ | -------- |
| Message | bytes.. | RLP data/message to sign |          |

Appends payload to transaction / message.

##### Final Packet P1 = 0x02

| Field   | Type    | Content          | Expected |
| ------- | ------- | ---------------- | -------- |
| Message | bytes.. | RLP data to sign |          |

Signs the message without metadata (arbitrary transaction signing). This requires expert mode and is able to handle any transaction. The app shows script hash and tries to show transaction arguments and their types, or a message that they are too long to display.

##### Metadata Packet P1 = 0x03

| Field          | Type              | Content          | Expected |
| -------------- | ----------------- | ---------------- | -------- |
| Num. of hashes | byte (1)          | number of hashes |          |
| Script hash 1  | byte (32)         | script SHA-256   |          |
| Script hash 2  | byte (32)         | script SHA-256   |          |
| ...            |                   |                  |          |
| Script hash n  | byte (32)         | script SHA-256   |          |
| Tx name        | null term. string | name of tx       |          |
| Num. of args   | byte (1)          | num. of tx args  |          |
| Argument 1     | bytes             | argument 1       |          |
| Argument 2     | bytes             | argument 2       |          |
| ...            |                   |                  |          |
| Argument m     | bytes             | argument m       |          |

and argument is either normal argument,

| Field          | Type              | Content                       | Expected |
| -------------- | ----------------- | ----------------------------- | -------- |
| Argument type  | byte (1)          | 1 - normal                    |          |
|                |                   | 2 - optional                  |          |
| Arg. name      | null term. string |                               |          |
| Arg. index     | byte (1)          | Order in which args are shown |          |
| Value type     | null term. string | Expected JSON value type      |          |
| JSON type      | byte (1)          |                               | 3-string |

array argument,

| Field          | Type              | Content                       | Expected |
| -------------- | ----------------- | ----------------------------- | -------- |
| Argument type  | byte (1)          | 3 - normal array              |          |
| Arr. min. len. | byte (1)          | Array min. length             |          |
| Arr. min. len. | byte (1)          | Array max. length             |          |
| Arg. name      | null term. string |                               |          |
| Arg. index     | byte (1)          | Order in which args are shown |          |
| Value type     | null term. string | Expected JSON value type      |          |
| JSON type      | byte (1)          |                               | 3-string |

string argument (this exist to save metadata space),

| Field          | Type              | Content                       | Expected |
| -------------- | ----------------- | ----------------------------- | -------- |
| Argument type  | byte (1)          | 4 - string                    |          |
| Arg. name      | null term. string |                               |          |
| Arg. index     | byte (1)          | Order in which args are shown |          |

or enum argument

| Field          | Type              | Content                       | Expected |
| -------------- | ----------------- | ----------------------------- | -------- |
| Argument type  | byte (1)          | 5 - hash algorithm            |          |
|                |                   | 6 - signature algorithm       |          |
|                |                   | 7 - node role                 |          |
| Arg. name      | null term. string |                               |          |
| Arg. index     | byte (1)          | Order in which args are shown |          |

Loads metadata, restarts Merkle tree proof of the metadata.

##### Merkle tree Packet P1 = 0x04 and 0x05


| Field               | Type         | Content          | Expected |
| ------------------- | ------------ | ---------------- | -------- |
| Merkle tree hash 1  | byte (32)    | Merkle tree hash |          |
| Merkle tree hash 2  | byte (32)    | Merkle tree hash |          |
| ...                 |              |                  |          |
| Merkle tree hash 7  | byte (32)    | Merkle tree hash |          |

Validates Merkle tree node. Validates that previous hash (metadata hash or merkle tree node hash) is in the list of hashes. Computes new hash and increments merkle tree counter. Call with P1 = 0x05 starts the signing process with metadata. This requires that we are at the root of the merkle tree and that the hash value matches the one stored in the app.

Four APDUs for four levels of internal merkle tree nodes. Each internal Merkle tree node has 7 children as 7 hashes fit into one APDU. APDU with P1=0x03 calculates metadata hash which corresponds to Merkle tree leaf value. Three subsequent P1=0x04 calls have to contain hashes from previous calls (either P1=0x03 or P1=0x04). After three calls with P1=0x04 there is call with P1=0x05, which works the same as P1=0x04 call, but it initiates transaction signing.

##### Final message signing Packet P1 = 0x10

| Field   | Type    | Content             | Expected |
| ------- | ------- | ------------------- | -------- |
| Message | bytes.. | Mesage data to sign |          |

Appends to data to message and initiates message signing.

#### Response

| Field       | Type           | Content     | Note                     |
| ----------- | -------------- | ----------- | ------------------------ |
| secp256k1 R | byte (32)      | Signature   |                          |
| secp256k1 S | byte (32)      | Signature   |                          |
| secp256k1 V | byte (1)       | Signature   |                          |
| SIG         | byte (varible) | Signature   | DER format               |
| SW1-SW2     | byte (2)       | Return code | see list of return codes |

---

### INS_GET_SLOTS_STATUS

Returns the slots status (free/used).

#### Command

| Field | Type     | Content                   | Expected |
| ----- | -------- | ------------------------- | -------- |
| CLA   | byte (1) | Application Identifier    | 0x33     |
| INS   | byte (1) | Instruction ID            | 0x11     |
| P1    | byte (1) | Parameter 1               | ignored  |
| P2    | byte (1) | Parameter 2               | ignored  |

#### Response

| Field | Type      | Content      | Note            |
| ----- | --------- | ------------ | --------------- |
| USED  | byte (64) | Slot is used | No = 0, Yes = 1 |

### INS_GET_SLOT

Returns the slot account.

#### Command

| Field | Type     | Content                   | Expected |
| ----- | -------- | ------------------------- | -------- |
| CLA   | byte (1) | Application Identifier    | 0x33     |
| INS   | byte (1) | Instruction ID            | 0x11     |
| P1    | byte (1) | Parameter 1               | ignored  |
| P2    | byte (1) | Parameter 2               | ignored  |
| L     | byte (1) | Bytes in payload          | 1        |
| Slot  | byte (1) | Slot Index                | 0..63    |

#### Response

| Field   | Type     | Content              | Note               |
| ------- | -------- | -------------------- | ------------------ |
| ADDR    | byte (8) | Address              |                    |
| Path[0] | byte (4) | Derivation Path Data | 0x80000000 \| 44   |
| Path[1] | byte (4) | Derivation Path Data | 0x80000000 \| 539' |
| Path[2] | byte (4) | Derivation Path Data | ?                  |
| Path[3] | byte (4) | Derivation Path Data | ?                  |
| Path[4] | byte (4) | Derivation Path Data | ?                  |
| Options | byte (2) | Crypto options (LE)  | ?                  |

Note:
Setting the slot to all zeros, will remove the data, otherwise,
the slot needs to have a valid derivation path

### INS_SET_SLOT

Set the slot with account information.

#### Command

| Field   | Type     | Content                | Expected |
| ------- | -------- | ---------------------- | -------- |
| CLA     | byte (1) | Application Identifier | 0x33     |
| INS     | byte (1) | Instruction ID         | 0x12     |
| P1      | byte (1) | Parameter 1            | ignored  |
| P2      | byte (1) | Parameter 2            | ignored  |
| L       | byte (1) | Bytes in payload       | 29       |
| Slot    | byte (1) | Slot Index             | 0..63    |
| ADDR    | byte (8) | Address                |          |
| Path[0] | byte (4) | Derivation Path Data   | ?        |
| Path[1] | byte (4) | Derivation Path Data   | ?        |
| Path[2] | byte (4) | Derivation Path Data   | ?        |
| Path[3] | byte (4) | Derivation Path Data   | ?        |
| Path[4] | byte (4) | Derivation Path Data   | ?        |
| Options | byte (2) | Crypto options (LE)    | ?        |
