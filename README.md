# RS256 Signature Verification

This repository contains an implementation of the RS256 signature verification algorithm as specified in [Section 8.1.2 of RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2). The implementation is written in Solidity and is designed for smart contracts on the Ethereum blockchain.

## Overview

RS256 is a signature algorithm that uses RSA (Rivest-Shamir-Adleman) for signing/verification. This implementation focuses on the signature verification part, using the SHA-256 hashing algorithm.



### Implementation

The code strictly follows the RSASSA-PKCS1-v1_5 signature verification operation steps outlined in RFC 8017. It takes a signature, message, and public key as inputs and verifies if the signature is valid for the given message using the provided public key.



## Usage

1. Using Foundry:

   ```shell
   forge install jayden-sudo/RS256
   ```



## Gas Consumption

For a typical 2048-bit key, a single signature verification requires about 10K gas.

To perform a gas consumption test:

```shell
npm run gas-report
```

Results:

| test/RS256_v1.t.sol:RS256Dev contract |                 |       |        |       |         |
| ------------------------------------- | --------------- | ----- | ------ | ----- | ------- |
| Deployment Cost                       | Deployment Size |       |        |       |         |
| 220669                                | 1130            |       |        |       |         |
| Function Name                         | min             | avg   | median | max   | # calls |
| verify                                | 10883           | 10883 | 10883  | 10883 | 1       |



## Testing

This code has passed the complete tests of the [Algorithm Validation Testing Requirements](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures#rsa2vs) - [FIPS 186-4](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip).

Test script: [RS256_FIPS_186_4.t.sol](test/RS256_FIPS_186_4.t.sol)

To execute tests:

```shell
npm run Check_SigVer15_186_3
```



## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
