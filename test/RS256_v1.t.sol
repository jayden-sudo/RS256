// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {RS256} from "../src/RS256_v1.sol";

contract RS256_v1Test is Test {
    RS256 public _RS256;

    function setUp() public {
        _RS256 = new RS256();
    }

    function test_rs256() public {
        bytes
            memory e = hex"0000000000000000000000000000000000000000000000000000000000010001";

        bytes
            memory Msg = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976305000000013cdb7da78783855f4167a4a0d6fdccaeff7a8596ce7ca47c7a4dbfe6b8d6b43a";

        bytes
            memory S = hex"add8085f6dc3657e1cb034b945e4fa57df40b7eac0382281a1b225a41dc4bba8"
            hex"9230f0c3c14f8c2a979636710a646fe7d400a9ddfc545f0ac245dee9f678bf63"
            hex"85429f5c1719b7a2822e242eaf6edc52de17abd071f69ead3d8e76c2f33424f8"
            hex"247dfd1dcea9fbbe5723e3931b48388343afe7770e82b0a7c66592c90e32a15a"
            hex"6dda5850ce6efa4dc86f513ce68aa764eba9875c6a43a0c73d83bebffabd19bb"
            hex"791811779070f9a1c6072be5046c81dbc2a576beba964620258c2a1d6795956e"
            hex"17a7619beb26cbb500af65554fa84beef8608a6e2d3849f8893c50d7b450cabf"
            hex"d53be339061dd8691e73445c3c9290425e98132afe876cfddd240e5fe90f73f8";

        bytes
            memory n = hex"babd47aa475d28fb0bc840be692c3e8fbeb7bbb81e303d3ba262c3aa83fd5832"
            hex"91f60a1b17c168ed75ac28f6e084e69a5296a807c667acdbab6794424e474e6f"
            hex"13d6544c139bb39133300145abcf2cb542e5bdc99bfa0e1ce637631667db5bbd"
            hex"c65f11d0a8abb5d2cbc0ae618a7ba975fe4121f95b7762c08e912e6d9415bf4f"
            hex"f1ef75f0deab9833e37f0ae2273a421520ed64bb06246463698aba3ee2e70567"
            hex"0899da6899b0d1151f261fa1c5b5ca269a805fc12cb6f10e87b3a80536d63e5e"
            hex"e52108fd1bfc745ab0de326205d7e16f6fbdac6c65d0b91f46a74f6772faeffa"
            hex"82be6f9069d6bd1790e7261f85ca32b1934dc1c82345af729c4023401d1e2949";

        uint256 gas_before = gasleft();
        bool isValid = _RS256.verify(n, e, Msg, S);
        uint256 gas_after = gasleft();
        assertEq(isValid, true);
        console2.log("gas used: ", gas_before - gas_after);
    }
}
