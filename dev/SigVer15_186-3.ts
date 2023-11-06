'use strict';
import { readFileSync, writeFileSync } from 'fs';

interface SigVer15_186_3_Item {
    mod: number;
    n: string;
    e: string;
    d: string;
    Msg: string;
    S: string;
    Result: boolean
}
function paddingZero(value: string | number | bigint, bytesLen: number): string {
    if (typeof value === 'string') {
        if (value.startsWith('0x')) {
            value = value.slice(2);
        }
        const len = bytesLen * 2;
        if (value.length > len) {
            throw new Error(`value ${value} length is greater than ${len}`);
        }
        return '0'.repeat(len - value.length) + value.toLowerCase();
    }
    else if (typeof value === 'number' || typeof value === 'bigint') {
        return paddingZero(value.toString(16), bytesLen);
    } else {
        throw new Error(`value ${value} is not string | number | bigint`);
    }
}

function toEvenLen(value: string): string {
    if (value.length % 2 === 0) {
        return value;
    } else {
        return '0' + value;
    }
}

// read txt file: SigVer15_186-3.rsp
const file = readFileSync('./dev/SigVer15_186-3.rsp', 'utf-8');
// read all lines
let lines = file.split('\n');
// skip first 5 lines
lines = lines.slice(5);

const SigVer15_186_3_Items: SigVer15_186_3_Item[] = [];

let _mod = 0;
let _n = '';
for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    if (line == '') {
        continue;
    } else if (line.startsWith('[mod = ')) {
        /* 
            [mod = 1024]
            [mod = 3072]
        */
        _mod = parseInt(line.split('=')[1].replace(']', '').trim());
    } else if (line.startsWith('n = ')) {
        // n = abcxxxxx
        _n = line.split('=')[1].trim();
    } else if (line.startsWith('SHAAlg = ')) {
        if (line.startsWith('SHAAlg = SHA256')) {
            /* 
                e = 49d2a1
                d = 0
                Msg = f89fd2f6c45a8b5066a651410b8e534bfec0d9a36f3e2b887457afd44dd651d1ec79274db5a455f182572fceea5e9e39c3c7c5d9e599e4fe31c37c34d253b419c3e8fb6b916aef6563f87d4c37224a456e5952698ba3d01b38945d998a795bd285d69478e3131f55117284e27b441f16095dca7ce9c5b68890b09a2bfbb010a5
                S = ba48538708512d45c0edcac57a9b4fb637e9721f72003c60f13f5c9a36c968cef9be8f54665418141c3d9ecc02a5bf952cfc055fb51e18705e9d8850f4e1f5a344af550de84ffd0805e27e557f6aa50d2645314c64c1c71aa6bb44faf8f29ca6578e2441d4510e36052f46551df341b2dcf43f761f08b946ca0b7081dadbb88e955e820fd7f657c4dd9f4554d167dd7c9a487ed41ced2b40068098deedc951060faf7e15b1f0f80ae67ff2ee28a238d80bf72dd71c8d95c79bc156114ece8ec837573a4b66898d45b45a5eacd0b0e41447d8fa08a367f437645e50c9920b88a16bc0880147acfb9a79de9e351b3fa00b3f4e9f182f45553dffca55e393c5eab6
                Result = F
            */
            const e_line = lines[i + 1];
            const d_line = lines[i + 2];
            const Msg_line = lines[i + 3];
            const S_line = lines[i + 4];
            const Result_line = lines[i + 5];

            const e = e_line.split('=')[1].trim();
            const d = d_line.split('=')[1].trim();
            const Msg = Msg_line.split('=')[1].trim();
            if (Msg == '95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad756fbd918c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632ad30b3dc3ce0ba97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af590824ca98d74fbca934d0b6867aa1991f3040b707e806de6e66b5934f05509bea') {
                debugger;
            }
            const S = S_line.split('=')[1].trim();
            const Result = Result_line.split('=')[1].trim() === 'P' ? true : false;

            SigVer15_186_3_Items.push({
                mod: _mod,
                n: _n,
                e,
                d,
                Msg,
                S,
                Result
            });
        }
        i += 6;
    }
}

// generate test cases
let test_cases = '';
for (let i = 0; i < SigVer15_186_3_Items.length; i++) {
    const item = SigVer15_186_3_Items[i];
    const { mod, n, e, d, Msg, S, Result } = item;
    test_cases += `\n`;
    test_cases += `function test_rs256_${i}() public {`;
    test_cases += `\n`;
    test_cases += `// mod = ${mod}`;
    test_cases += `\n`;
    // test_cases += `// n = ${n}`;
    // test_cases += `\n`;
    // test_cases += `// e = ${e}`;
    // test_cases += `\n`;
    // test_cases += `// d = ${d}`;
    // test_cases += `\n`;
    // test_cases += `// Msg = ${Msg}`;
    // test_cases += `\n`;
    // test_cases += `// S = ${S}`;
    // test_cases += `\n`;
    // test_cases += `// Result = ${Result}`;
    // test_cases += `\n`;

    test_cases += `bytes memory e = hex"${paddingZero('0x' + e, 32)}";`;
    test_cases += `\n`;
    test_cases += `bytes memory Msg = hex"${toEvenLen(Msg)}";`;
    test_cases += `\n`;
    test_cases += `bytes memory S = hex"${paddingZero('0x' + S, mod / 8)}";`;
    test_cases += `\n`;
    test_cases += `bytes memory n = hex"${paddingZero('0x' + n, mod / 8)}";`;
    test_cases += `\n`;
    test_cases += `assertEq(_RS256Dev.verify(n, e, Msg, S), ${Result ? 'true' : 'false'});`;
    test_cases += `\n`;
    test_cases += `}`;
}

console.log(test_cases);

writeFileSync('./tmp/test_rs256.sol', test_cases);