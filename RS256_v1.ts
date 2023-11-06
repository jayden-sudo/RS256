'use strict';
// refer: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2

class RS256V1 {

    modexp(base: bigint, exponent: bigint, modulus: bigint): bigint {
        if (modulus === BigInt(1)) return BigInt(0);
        let result = BigInt(1);
        base = base % modulus;
        if (base === BigInt(0)) return BigInt(0);
        while (exponent > BigInt(0)) {
            if (exponent % BigInt(2) === BigInt(1)) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> BigInt(1);
            base = (base * base) % modulus;
        }
        return result;
    }

    toHexString(_bigint: bigint): string {
        const _hex = _bigint.toString(16);
        // padding to even length
        return (_hex.length % 2) ? '0' + _hex : _hex;
    }

    /**
     *
     *
     * @param {bigint} n (n, e) RSA public key
     * @param {bigint} e (n, e) RSA public key
     * @param {bigint} s s signature representative, an integer between 0 and n - 1
     * @return {*}  {bigint} m message representative, an integer between 0 and n - 1
     */
    RSAVP1(n: bigint, e: bigint, s: bigint): bigint {
        /*
            Steps:
     
            1.  If the signature representative s is not between 0 and n - 1,
                output "signature representative out of range" and stop.
     
            2.  Let m = s^e mod n.
     
            3.  Output m.
        */
        if (s < BigInt(0) || s > n - BigInt(1)) {
            console.log('signature representative out of range');
            throw new Error('signature representative out of range');
        }
        const m = this.modexp(s, e, n);
        return m;
    }

    /**
     * This encoding method is deterministic and only has an encoding operation.
     *
     * @param {string} H Apply the hash function to the message M to produce a hash value H
     * @param {bigint} emLen intended length in octets of the encoded message, 
     * at least tLen + 11, where tLen is the octet length of the Distinguished 
     * Encoding Rules (DER) encoding T of a certain value computed during the encoding operation.
     * @return {*}  {bigint} encoded message, an octet string of length emLen
     */
    EMSA_PKCS1_v1_5_ENCODE(H: bigint, emLen: bigint): bigint {
        /*  
            1.  Encode the algorithm ID for the hash function and the hash
                value into an ASN.1 value of type DigestInfo (see
                Appendix A.2.4) with the DER, where the type DigestInfo has
                the syntax
     
                    DigestInfo ::= SEQUENCE {
                        digestAlgorithm AlgorithmIdentifier,
                        digest OCTET STRING
                    }
     
                The first field identifies the hash function and the second
                contains the hash value.  Let T be the DER encoding of the
                DigestInfo value (see the notes below), and let tLen be the
                length in octets of T.
     
            2.  If emLen < tLen + 11, output "intended encoded message length
                too short" and stop.
     
            3.  Generate an octet string PS consisting of emLen - tLen - 3
                octets with hexadecimal value 0xff.  The length of PS will be
                at least 8 octets.
     
            4.  Concatenate PS, the DER encoding T, and other padding to form
                the encoded message EM as
     
                    EM = 0x00 || 0x01 || PS || 0x00 || T.
     
            5.  Output EM.
     
            SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
        */

        // sha256 Algorithm Identifier Der
        const T_DER = "3031300d060960864801650304020105000420";
        const T = T_DER + this.toHexString(H);
        const tLen = BigInt(T.length / 2); // 51 (sha256)
        if (emLen < tLen + BigInt(11)) {
            throw new Error('intended encoded message length too short');
        }

        let PS_ByteLen = emLen - tLen - BigInt(3);
        if (PS_ByteLen < BigInt(8)) {
            PS_ByteLen = BigInt(8);
        }
        let PS = 'ff'.repeat(Number(PS_ByteLen));

        const EM = BigInt('0x0001' + PS + '00' + T);

        return EM;
    }

    /**
     * refer: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2
     *
     * @param {*} n (n, e)  signer's RSA public key
     * @param {*} e (n, e)  signer's RSA public key
     * @param {*} H SHA256(message whose signature is to be verified, an octet string)
     * @param {*} S signature to be verified, an octet string of length k, where k is the length in octets of the RSA modulus n
     */
    RSASSA_PKCS1_V1_5_VERIFY(n: bigint, e: bigint, H: bigint, S: bigint): boolean {
        // 1. Length checking: If the length of S is not k octets, output "invalid signature" and stop.
        const k = this.toHexString(n).length / 2;

        if (this.toHexString(S).length / 2 !== k) {
            console.log('invalid signature');
            return false;
        }
        // 2. RSA verification:
        /* 
            a.  Convert the signature S to an integer signature representative s (see Section 4.2):
                s = OS2IP (S).
        */

        /* 
            b.  Apply the RSAVP1 verification primitive (Section 5.2.2) to
                the RSA public key (n, e) and the signature representative
                s to produce an integer message representative m:
                m = RSAVP1 ((n, e), s).
                If RSAVP1 outputs "signature representative out of range",output "invalid signature" and stop.
        */
        const m = this.RSAVP1(n, e, S);

        /*
            c.  Convert the message representative m to an encoded message
                  EM of length k octets (see Section 4.1):
                     EM = I2OSP (m, k).
        */

        const EM = m; //  m = I2OSP(m, k);


        /*
            3.  EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
              operation (Section 9.2) to the message M to produce a second
              encoded message EM' of length k octets:
     
                 EM' = EMSA-PKCS1-V1_5-ENCODE (M, k).
     
              If the encoding operation outputs "message too long", output
              "message too long" and stop.  If the encoding operation
              outputs "intended encoded message length too short", output
              "RSA modulus too short" and stop.
        */
        const EM_ = this.EMSA_PKCS1_v1_5_ENCODE(H, BigInt(k));

        /* 
             4.  Compare the encoded message EM and the second encoded message
              EM'.  If they are the same, output "valid signature";
              otherwise, output "invalid signature".
        */

        if (EM === EM_) {
            console.log('valid signature');
            return true;
        } else {
            throw new Error('invalid signature');
        }
    }
}

new RS256V1().RSASSA_PKCS1_V1_5_VERIFY(
    BigInt('0xbabd47aa475d28fb0bc840be692c3e8fbeb7bbb81e303d3ba262c3aa83fd583291f60a1b17c168ed75ac28f6e084e69a5296a807c667acdbab6794424e474e6f13d6544c139bb39133300145abcf2cb542e5bdc99bfa0e1ce637631667db5bbdc65f11d0a8abb5d2cbc0ae618a7ba975fe4121f95b7762c08e912e6d9415bf4ff1ef75f0deab9833e37f0ae2273a421520ed64bb06246463698aba3ee2e705670899da6899b0d1151f261fa1c5b5ca269a805fc12cb6f10e87b3a80536d63e5ee52108fd1bfc745ab0de326205d7e16f6fbdac6c65d0b91f46a74f6772faeffa82be6f9069d6bd1790e7261f85ca32b1934dc1c82345af729c4023401d1e2949'),
    BigInt('0x010001'),
    BigInt('0x0d03104dd2e3fb8bd1e9c0bc5b09e2b2eca44ffb777497672ffe9626d349f93f'),
    BigInt('0xadd8085f6dc3657e1cb034b945e4fa57df40b7eac0382281a1b225a41dc4bba89230f0c3c14f8c2a979636710a646fe7d400a9ddfc545f0ac245dee9f678bf6385429f5c1719b7a2822e242eaf6edc52de17abd071f69ead3d8e76c2f33424f8247dfd1dcea9fbbe5723e3931b48388343afe7770e82b0a7c66592c90e32a15a6dda5850ce6efa4dc86f513ce68aa764eba9875c6a43a0c73d83bebffabd19bb791811779070f9a1c6072be5046c81dbc2a576beba964620258c2a1d6795956e17a7619beb26cbb500af65554fa84beef8608a6e2d3849f8893c50d7b450cabfd53be339061dd8691e73445c3c9290425e98132afe876cfddd240e5fe90f73f8')
);