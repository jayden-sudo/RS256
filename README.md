# RS256 Signature Verification

This repository contains an implementation of the RS256 signature verification algorithm as specified in [RFC 8017 Section 8.1.2](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2). The implementation is written in Solidity and is designed for use within smart contracts on the Ethereum blockchain.

## Overview

RS256 is a signature algorithm that uses RSA (Rivest-Shamir-Adleman) for signing/verifying. This implementation specifically handles the signature verification part using SHA-256 for hashing.

## Implementation

The code follows the steps outlined in RFC 8017 for the RSASSA-PKCS1-v1_5 signature verification operation. It takes a signature, message, and public key as inputs and verifies whether the signature is valid for the given message using the provided public key.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.