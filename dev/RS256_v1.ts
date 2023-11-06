'use strict';
import { webcrypto } from 'node:crypto';

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

    hexToUint8Array(hex: string): Uint8Array {
        if (hex.startsWith('0x')) hex = hex.slice(2);
        let len = hex.length;
        if (len % 2 !== 0) {
            len++;
            hex = '0' + hex;
        }
        const uint8Array = new Uint8Array(len / 2);
        for (let i = 0; i < len; i += 2) {
            uint8Array[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return uint8Array;
    }

    arrayBufferToHex(uint8Array: Uint8Array) {
        return '0x' + Array.from(uint8Array).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async sha256(m: bigint): Promise<string> {
        const _hash = await webcrypto.subtle.digest("SHA-256", this.hexToUint8Array(m.toString(16)));
        return this.arrayBufferToHex(new Uint8Array(_hash));
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
     * @param {string} M message whose signature is to be verified, an octet string
     * @param {bigint} emLen intended length in octets of the encoded message, 
     * at least tLen + 11, where tLen is the octet length of the Distinguished 
     * Encoding Rules (DER) encoding T of a certain value computed during the encoding operation.
     * @return {*}  {bigint} encoded message, an octet string of length emLen
     */
    async EMSA_PKCS1_v1_5_ENCODE(M: bigint, emLen: bigint): Promise<bigint> {
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
        const H = (await this.sha256(M)).slice(2);
        const T = T_DER + H;
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
     * @param {*} M message whose signature is to be verified, an octet string
     * @param {*} S signature to be verified, an octet string of length k, where k is the length in octets of the RSA modulus n
     */
    async RSASSA_PKCS1_V1_5_VERIFY(n: bigint, e: bigint, M: bigint, S: bigint): Promise<boolean> {
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
        const EM_ = await this.EMSA_PKCS1_v1_5_ENCODE(M, BigInt(k));

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


async function main() {



    const re1 = await new RS256V1().RSASSA_PKCS1_V1_5_VERIFY(
        BigInt('0xbabd47aa475d28fb0bc840be692c3e8fbeb7bbb81e303d3ba262c3aa83fd583291f60a1b17c168ed75ac28f6e084e69a5296a807c667acdbab6794424e474e6f13d6544c139bb39133300145abcf2cb542e5bdc99bfa0e1ce637631667db5bbdc65f11d0a8abb5d2cbc0ae618a7ba975fe4121f95b7762c08e912e6d9415bf4ff1ef75f0deab9833e37f0ae2273a421520ed64bb06246463698aba3ee2e705670899da6899b0d1151f261fa1c5b5ca269a805fc12cb6f10e87b3a80536d63e5ee52108fd1bfc745ab0de326205d7e16f6fbdac6c65d0b91f46a74f6772faeffa82be6f9069d6bd1790e7261f85ca32b1934dc1c82345af729c4023401d1e2949'),
        BigInt('0x010001'),
        BigInt('0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976305000000013cdb7da78783855f4167a4a0d6fdccaeff7a8596ce7ca47c7a4dbfe6b8d6b43a'),
        BigInt('0xadd8085f6dc3657e1cb034b945e4fa57df40b7eac0382281a1b225a41dc4bba89230f0c3c14f8c2a979636710a646fe7d400a9ddfc545f0ac245dee9f678bf6385429f5c1719b7a2822e242eaf6edc52de17abd071f69ead3d8e76c2f33424f8247dfd1dcea9fbbe5723e3931b48388343afe7770e82b0a7c66592c90e32a15a6dda5850ce6efa4dc86f513ce68aa764eba9875c6a43a0c73d83bebffabd19bb791811779070f9a1c6072be5046c81dbc2a576beba964620258c2a1d6795956e17a7619beb26cbb500af65554fa84beef8608a6e2d3849f8893c50d7b450cabfd53be339061dd8691e73445c3c9290425e98132afe876cfddd240e5fe90f73f8')
    );
    if (re1 === false) {
        throw new Error("error 1");
    }

    /*
        n = c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026bcb2399bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae852087d25f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d11542a705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671de874bb9cecb058c6c8344aa8c93754d6effcd44a41ed7de0a9dcd9144437f212b18881d042d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189ff968b92f33c266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce98f54ed237b4a04a4159a5f6250a296a902880204e61d891c4da29f2d65f34cbb
        SHAAlg = SHA256
        e = 49d2a1
        d = 0
        Msg = 95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad756fbd918c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632ad30b3dc3ce0ba97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af590824ca98d74fbca934d0b6867aa1991f3040b707e806de6e66b5934f05509bea
        S = 51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027d39365de70a31db05e9e10eb6148cb7f6425f0c93c4fb0e2291adbd22c77656afc196858a11e1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd509e896f63884e9424f69c1c5397959f1e52a368667a598a1fc90125273d9341295d2f8e1cc4969bf228c860e07a3546be2eeda1cde48ee94d062801fe666e4a7ae8cb9cd79262c017b081af874ff00453ca43e34efdb43fffb0bb42a4e2d32a5e5cc9e8546a221fe930250e5f5333e0efe58ffebf19369a3b8ae5a67f6a048bc9ef915bda25160729b508667ada84a0c27e7e26cf2abca413e5e4693f4a9405
        Result = P
    */

    const re2 = await new RS256V1().RSASSA_PKCS1_V1_5_VERIFY(
        BigInt('0xc47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026bcb2399bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae852087d25f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d11542a705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671de874bb9cecb058c6c8344aa8c93754d6effcd44a41ed7de0a9dcd9144437f212b18881d042d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189ff968b92f33c266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce98f54ed237b4a04a4159a5f6250a296a902880204e61d891c4da29f2d65f34cbb'),
        BigInt('0x49d2a1'),
        BigInt('0x95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad756fbd918c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632ad30b3dc3ce0ba97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af590824ca98d74fbca934d0b6867aa1991f3040b707e806de6e66b5934f05509bea'),
        BigInt('0x51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027d39365de70a31db05e9e10eb6148cb7f6425f0c93c4fb0e2291adbd22c77656afc196858a11e1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd509e896f63884e9424f69c1c5397959f1e52a368667a598a1fc90125273d9341295d2f8e1cc4969bf228c860e07a3546be2eeda1cde48ee94d062801fe666e4a7ae8cb9cd79262c017b081af874ff00453ca43e34efdb43fffb0bb42a4e2d32a5e5cc9e8546a221fe930250e5f5333e0efe58ffebf19369a3b8ae5a67f6a048bc9ef915bda25160729b508667ada84a0c27e7e26cf2abca413e5e4693f4a9405')
    );
    if (re2 === false) {
        throw new Error("error 1");
    }


    /*
        n = 9bbb099e1ec285594e73f9d11cbe81e7f1fa06fd34f3ec0b799394aed30fc2ed9de7b2a6866fde69846fb55a6ab98e552f9d20f05aa0d55c967817e4e04bdf9bf52fabcfcfa41265a7561b033ca3d56fb8e8a2e4de63e960cfb5a689129b188e5641f20dbf8908dab8e30e82f1d0e288e23869c7cac2b0318602610a776a19c1f93968c652b64f51406e7a4b2508d25b632606834a9638074e2633eb323324b8b30fdbd8e8fdad8602b11f25f3906439055afe947f9b9bcffb45dad88a1df5304c879bb4a6eddb4d3d1846bf907d2ca269845c790b2f0af8154aad9c4acb75e18a5d0e4f9f88137032b9964fe171dfa0d0f286090790f52157179a6734b5f9a64e3d2ed529722c3d3836d4501496f927a0f8e389ca35332b836d99e995f4a3e86f581bf9abdc7a10e06a6b31296ae3b43e6ddc9a0d9a7d0d9c4053af0875e851192d1de7b08d1beb7b857e227f8803a5620726a31920bcab922d3370a78033b315024a0fc1f6c276be565e58de77f294c8089ff4c43fb334d26006ab5757c65b
        SHAAlg = SHA256
        e = ac6db1
        d = 0
        Msg = 88902b37b0db4246c41b50f180eb1350b1b6dac0477a3dd1accb0c5f541a85fe9637ca9cba15926153ce1edacfe66f574cd4b691adbe0c90ed8563ccb401bc93288e9baa06c7b837f191f8de0a5c9b2bc0a5b730eabfe56f13d43afa142779d8e99b86abbd791e90476ec64759d30194b631c6e425053134c3c0792f9d122296
        S = 9d64c3b9a4ba78889747aef7c8565eb075e5bd92a55f9d34d3df6a2d740cd863ff98a04be4866e9f906cc6d99270d208a3dc2e53201cac9f4f758eecbe8a44db0243a3e40400cac37856079f2fe02d54d9748754331d9935595c35b22cc6c45686ea964642ec4ca7e0a88e4a4c0a6166733e361c46a592469cad7009ca3170cf3fbe485b1c8726e23a6e35f9691d9bf4029d82756c64a4d31ad0b8ef57a0ba2d55419d7cfabbab1a23c8baa4bf043a444b127920250551467d7d528425dc7c903c2c824e6b9b65f543ad9d7055300f19500356100411271e15b939d496b4bd4cc3ba4b6aa2ce65f4825275404cb19512ae27cc986b0af6fddff35980c2cc0e96829ecbd9ee19944838e4c83b1eadb6f78669890f556781c4e97d8ede9664080e47b3adaf2f5e04bd42d46012aeace3078f9068d870fee02b088f9674fdc0ca0064e9f0f63205836d7a8771264c553c945eb7c87df2a13d8efd3cdc8409843e7a246089970abd43526f3cc9cf993d419a6beaaaf6830208686a1fde4733f078ac
        Result = F

    */

    try {
        const re3 = await new RS256V1().RSASSA_PKCS1_V1_5_VERIFY(
            BigInt('0x9bbb099e1ec285594e73f9d11cbe81e7f1fa06fd34f3ec0b799394aed30fc2ed9de7b2a6866fde69846fb55a6ab98e552f9d20f05aa0d55c967817e4e04bdf9bf52fabcfcfa41265a7561b033ca3d56fb8e8a2e4de63e960cfb5a689129b188e5641f20dbf8908dab8e30e82f1d0e288e23869c7cac2b0318602610a776a19c1f93968c652b64f51406e7a4b2508d25b632606834a9638074e2633eb323324b8b30fdbd8e8fdad8602b11f25f3906439055afe947f9b9bcffb45dad88a1df5304c879bb4a6eddb4d3d1846bf907d2ca269845c790b2f0af8154aad9c4acb75e18a5d0e4f9f88137032b9964fe171dfa0d0f286090790f52157179a6734b5f9a64e3d2ed529722c3d3836d4501496f927a0f8e389ca35332b836d99e995f4a3e86f581bf9abdc7a10e06a6b31296ae3b43e6ddc9a0d9a7d0d9c4053af0875e851192d1de7b08d1beb7b857e227f8803a5620726a31920bcab922d3370a78033b315024a0fc1f6c276be565e58de77f294c8089ff4c43fb334d26006ab5757c65b'),
            BigInt('0xac6db1'),
            BigInt('0x88902b37b0db4246c41b50f180eb1350b1b6dac0477a3dd1accb0c5f541a85fe9637ca9cba15926153ce1edacfe66f574cd4b691adbe0c90ed8563ccb401bc93288e9baa06c7b837f191f8de0a5c9b2bc0a5b730eabfe56f13d43afa142779d8e99b86abbd791e90476ec64759d30194b631c6e425053134c3c0792f9d122296'),
            BigInt('0x9d64c3b9a4ba78889747aef7c8565eb075e5bd92a55f9d34d3df6a2d740cd863ff98a04be4866e9f906cc6d99270d208a3dc2e53201cac9f4f758eecbe8a44db0243a3e40400cac37856079f2fe02d54d9748754331d9935595c35b22cc6c45686ea964642ec4ca7e0a88e4a4c0a6166733e361c46a592469cad7009ca3170cf3fbe485b1c8726e23a6e35f9691d9bf4029d82756c64a4d31ad0b8ef57a0ba2d55419d7cfabbab1a23c8baa4bf043a444b127920250551467d7d528425dc7c903c2c824e6b9b65f543ad9d7055300f19500356100411271e15b939d496b4bd4cc3ba4b6aa2ce65f4825275404cb19512ae27cc986b0af6fddff35980c2cc0e96829ecbd9ee19944838e4c83b1eadb6f78669890f556781c4e97d8ede9664080e47b3adaf2f5e04bd42d46012aeace3078f9068d870fee02b088f9674fdc0ca0064e9f0f63205836d7a8771264c553c945eb7c87df2a13d8efd3cdc8409843e7a246089970abd43526f3cc9cf993d419a6beaaaf6830208686a1fde4733f078ac')
        );
        if (re3 === true) {
            throw new Error("error 3")
        }
    } catch (error) { }


}

main();

