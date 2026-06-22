/**
 * aes256.js
 * ------------------------------------------------------------
 * Implementasi ALGORITMA AES-256 (Advanced Encryption Standard)
 * secara MANUAL sesuai standar FIPS-197, mode CBC (Cipher Block
 * Chaining) dengan padding PKCS#7.
 *
 * TIDAK menggunakan crypto.createCipheriv / createDecipheriv
 * ataupun fungsi AES bawaan library apapun. Seluruh proses:
 *  - Key Expansion (256-bit key -> 15 round key, Nr = 14)
 *  - SubBytes / InvSubBytes (S-box)
 *  - ShiftRows / InvShiftRows
 *  - MixColumns / InvMixColumns (operasi GF(2^8))
 *  - AddRoundKey
 *  - Mode CBC (XOR antar blok)
 *  - Padding PKCS#7
 * ditulis manual di file ini.
 *
 * crypto.randomBytes() boleh dipakai HANYA untuk membangkitkan IV
 * (initialization vector) acak, karena itu fungsi pembangkit
 * angka acak, bukan bagian dari algoritma AES.
 * ------------------------------------------------------------
 */

const crypto = require('crypto');

// ============================================================
// 1. TABEL S-BOX DAN INVERSE S-BOX (FIPS-197)
// ============================================================
const SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

// Inverse S-box dihitung otomatis dari SBOX (bukan ditulis ulang tabelnya manual,
// tapi tetap murni hasil komputasi lokal, bukan dari library)
const INV_SBOX = new Array(256);
for (let i = 0; i < 256; i++) {
    INV_SBOX[SBOX[i]] = i;
}

// Round constant (Rcon) untuk key expansion
const RCON = [
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d
];

// ============================================================
// 2. OPERASI GF(2^8) UNTUK MixColumns / InvMixColumns
// ============================================================

// Perkalian dua byte dalam Galois Field GF(2^8) dengan
// polinomial irreducible AES: x^8 + x^4 + x^3 + x + 1 (0x11B)
function gmul(a, b) {
    let p = 0;
    for (let counter = 0; counter < 8; counter++) {
        if (b & 1) {
            p ^= a;
        }
        const hiBitSet = a & 0x80;
        a = (a << 1) & 0xFF;
        if (hiBitSet) {
            a ^= 0x1B; // x^8 mod (x^8 + x^4 + x^3 + x + 1)
        }
        b >>= 1;
    }
    return p & 0xFF;
}

// ============================================================
// 3. KEY EXPANSION (untuk AES-256 -> Nk=8, Nr=14, total 15 round key)
// ============================================================
const Nb = 4;   // jumlah kolom (32-bit words) dalam state, selalu 4 untuk AES
const Nk = 8;   // jumlah kolom 32-bit pada key, 8 untuk AES-256 (32 byte)
const Nr = 14;  // jumlah ronde, 14 untuk AES-256

// RotWord: rotasi 1 byte ke kiri pada array 4 byte [a0,a1,a2,a3] -> [a1,a2,a3,a0]
function rotWord(word) {
    return [word[1], word[2], word[3], word[0]];
}

// SubWord: substitusi tiap byte pada word 4-byte menggunakan S-box
function subWord(word) {
    return [SBOX[word[0]], SBOX[word[1]], SBOX[word[2]], SBOX[word[3]]];
}

/**
 * Melakukan key expansion AES-256.
 * Input: key (Buffer 32 byte)
 * Output: array of round keys, total Nr+1 = 15 round key,
 *         masing-masing berupa array 16 byte (4 kolom x 4 baris)
 */
function keyExpansion(key) {
    const w = []; // array of 4-byte words

    // 8 word pertama langsung diambil dari key asli
    for (let i = 0; i < Nk; i++) {
        w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    const totalWords = Nb * (Nr + 1); // 4 * 15 = 60 word

    for (let i = Nk; i < totalWords; i++) {
        let temp = w[i - 1].slice();

        if (i % Nk === 0) {
            temp = subWord(rotWord(temp));
            temp[0] ^= RCON[i / Nk];
        } else if (i % Nk === 4) {
            // Khusus AES-256: ada langkah SubWord tambahan setiap 4 word
            temp = subWord(temp);
        }

        const prev = w[i - Nk];
        const newWord = [
            prev[0] ^ temp[0],
            prev[1] ^ temp[1],
            prev[2] ^ temp[2],
            prev[3] ^ temp[3]
        ];
        w.push(newWord);
    }

    // Susun 60 word menjadi 15 round key, masing-masing 16 byte
    const roundKeys = [];
    for (let r = 0; r <= Nr; r++) {
        let roundKey = [];
        for (let c = 0; c < Nb; c++) {
            roundKey = roundKey.concat(w[r * Nb + c]);
        }
        roundKeys.push(roundKey); // 16 byte
    }
    return roundKeys;
}

// ============================================================
// 4. TRANSFORMASI STATE (state = matriks 4x4 byte, disimpan
//    sebagai array 16 byte dengan urutan kolom-mayor sesuai FIPS-197)
// ============================================================

// AddRoundKey: XOR state dengan round key
function addRoundKey(state, roundKey) {
    for (let i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

// SubBytes: substitusi setiap byte state menggunakan S-box
function subBytes(state) {
    for (let i = 0; i < 16; i++) {
        state[i] = SBOX[state[i]];
    }
}

// InvSubBytes: substitusi setiap byte state menggunakan Inverse S-box
function invSubBytes(state) {
    for (let i = 0; i < 16; i++) {
        state[i] = INV_SBOX[state[i]];
    }
}

/**
 * ShiftRows: setiap baris ke-r pada matriks state digeser
 * (rotate left) sebanyak r posisi.
 * State disimpan kolom-mayor: state[col*4 + row]
 */
function shiftRows(state) {
    const tmp = state.slice();
    for (let row = 1; row < 4; row++) {
        for (let col = 0; col < 4; col++) {
            // ambil dari kolom (col+row) mod 4, baris yang sama
            tmp[col * 4 + row] = state[((col + row) % 4) * 4 + row];
        }
    }
    for (let i = 0; i < 16; i++) state[i] = tmp[i];
}

// InvShiftRows: kebalikan dari ShiftRows (rotate right sebanyak r posisi)
function invShiftRows(state) {
    const tmp = state.slice();
    for (let row = 1; row < 4; row++) {
        for (let col = 0; col < 4; col++) {
            tmp[col * 4 + row] = state[((col - row + 4) % 4) * 4 + row];
        }
    }
    for (let i = 0; i < 16; i++) state[i] = tmp[i];
}

/**
 * MixColumns: mengalikan setiap kolom state (4 byte) dengan
 * matriks tetap berbasis GF(2^8):
 *   [2 3 1 1]
 *   [1 2 3 1]
 *   [1 1 2 3]
 *   [3 1 1 2]
 */
function mixColumns(state) {
    for (let c = 0; c < 4; c++) {
        const a0 = state[c * 4 + 0];
        const a1 = state[c * 4 + 1];
        const a2 = state[c * 4 + 2];
        const a3 = state[c * 4 + 3];

        state[c * 4 + 0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        state[c * 4 + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        state[c * 4 + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        state[c * 4 + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
}

/**
 * InvMixColumns: kebalikan dari MixColumns, menggunakan matriks
 * invers di GF(2^8):
 *   [0e 0b 0d 09]
 *   [09 0e 0b 0d]
 *   [0d 09 0e 0b]
 *   [0b 0d 09 0e]
 */
function invMixColumns(state) {
    for (let c = 0; c < 4; c++) {
        const a0 = state[c * 4 + 0];
        const a1 = state[c * 4 + 1];
        const a2 = state[c * 4 + 2];
        const a3 = state[c * 4 + 3];

        state[c * 4 + 0] = gmul(a0,0x0e) ^ gmul(a1,0x0b) ^ gmul(a2,0x0d) ^ gmul(a3,0x09);
        state[c * 4 + 1] = gmul(a0,0x09) ^ gmul(a1,0x0e) ^ gmul(a2,0x0b) ^ gmul(a3,0x0d);
        state[c * 4 + 2] = gmul(a0,0x0d) ^ gmul(a1,0x09) ^ gmul(a2,0x0e) ^ gmul(a3,0x0b);
        state[c * 4 + 3] = gmul(a0,0x0b) ^ gmul(a1,0x0d) ^ gmul(a2,0x09) ^ gmul(a3,0x0e);
    }
}

// ============================================================
// 5. ENKRIPSI / DEKRIPSI 1 BLOK (16 byte) - INTI ALGORITMA AES
// ============================================================

/**
 * Mengenkripsi satu blok 16 byte menggunakan AES-256.
 * @param {number[]} block - array 16 byte (plaintext block)
 * @param {number[][]} roundKeys - hasil dari keyExpansion()
 * @returns {number[]} array 16 byte (ciphertext block)
 */
function encryptBlock(block, roundKeys) {
    const state = block.slice();

    // Ronde awal: AddRoundKey dengan round key ke-0
    addRoundKey(state, roundKeys[0]);

    // Ronde 1 sampai Nr-1: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    for (let round = 1; round < Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys[round]);
    }

    // Ronde terakhir (Nr): tanpa MixColumns
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys[Nr]);

    return state;
}

/**
 * Mendekripsi satu blok 16 byte menggunakan AES-256 (kebalikan dari encryptBlock).
 * @param {number[]} block - array 16 byte (ciphertext block)
 * @param {number[][]} roundKeys - hasil dari keyExpansion()
 * @returns {number[]} array 16 byte (plaintext block)
 */
function decryptBlock(block, roundKeys) {
    const state = block.slice();

    // Ronde awal (kebalikan dari ronde terakhir enkripsi)
    addRoundKey(state, roundKeys[Nr]);
    invShiftRows(state);
    invSubBytes(state);

    // Ronde Nr-1 turun sampai 1
    for (let round = Nr - 1; round >= 1; round--) {
        addRoundKey(state, roundKeys[round]);
        invMixColumns(state);
        invShiftRows(state);
        invSubBytes(state);
    }

    // Ronde terakhir (kebalikan dari AddRoundKey awal enkripsi)
    addRoundKey(state, roundKeys[0]);

    return state;
}

// ============================================================
// 6. PADDING PKCS#7
// ============================================================

// Menambahkan padding PKCS#7 agar panjang data menjadi kelipatan 16 byte
function pkcs7Pad(buffer) {
    const padLen = 16 - (buffer.length % 16);
    const padded = Buffer.concat([buffer, Buffer.alloc(padLen, padLen)]);
    return padded;
}

// Menghapus padding PKCS#7 setelah dekripsi
function pkcs7Unpad(buffer) {
    const padLen = buffer[buffer.length - 1];
    if (padLen < 1 || padLen > 16) {
        throw new Error('Padding tidak valid');
    }
    return buffer.slice(0, buffer.length - padLen);
}

// ============================================================
// 7. MODE CBC (Cipher Block Chaining) - manual
// ============================================================

/**
 * Enkripsi AES-256-CBC manual.
 * @param {string} plaintext - teks asli (utf8)
 * @param {Buffer} key - 32 byte (256-bit) secret key
 * @returns {{ciphertext: string, iv: string}} ciphertext base64, iv hex
 */
function encrypt(plaintext, key) {
    if (key.length !== 32) {
        throw new Error('AES-256 membutuhkan key sepanjang 32 byte');
    }

    const roundKeys = keyExpansion(Array.from(key));

    // IV (initialization vector) 16 byte acak.
    // crypto.randomBytes hanya dipakai sebagai pembangkit angka acak,
    // BUKAN sebagai fungsi AES.
    const iv = crypto.randomBytes(16);

    const dataBuffer = pkcs7Pad(Buffer.from(plaintext, 'utf8'));
    const cipherBytes = Buffer.alloc(dataBuffer.length);

    let prevBlock = Array.from(iv);

    for (let offset = 0; offset < dataBuffer.length; offset += 16) {
        const plainBlock = Array.from(dataBuffer.slice(offset, offset + 16));

        // CBC: XOR plaintext block dengan ciphertext block sebelumnya (atau IV)
        const xored = plainBlock.map((b, idx) => b ^ prevBlock[idx]);

        const encryptedBlock = encryptBlock(xored, roundKeys);

        Buffer.from(encryptedBlock).copy(cipherBytes, offset);
        prevBlock = encryptedBlock;
    }

    return {
        ciphertext: cipherBytes.toString('base64'),
        iv: iv.toString('hex')
    };
}

/**
 * Dekripsi AES-256-CBC manual.
 * @param {string} ciphertextBase64 - ciphertext dalam format base64
 * @param {string} ivHex - IV dalam format hex
 * @param {Buffer} key - 32 byte (256-bit) secret key
 * @returns {string} plaintext asli (utf8)
 */
function decrypt(ciphertextBase64, ivHex, key) {
    if (key.length !== 32) {
        throw new Error('AES-256 membutuhkan key sepanjang 32 byte');
    }

    const roundKeys = keyExpansion(Array.from(key));

    const iv = Buffer.from(ivHex, 'hex');
    const cipherBytes = Buffer.from(ciphertextBase64, 'base64');
    const plainBytes = Buffer.alloc(cipherBytes.length);

    let prevBlock = Array.from(iv);

    for (let offset = 0; offset < cipherBytes.length; offset += 16) {
        const cipherBlock = Array.from(cipherBytes.slice(offset, offset + 16));

        const decryptedBlock = decryptBlock(cipherBlock, roundKeys);

        // CBC: XOR hasil dekripsi blok dengan ciphertext block sebelumnya (atau IV)
        const xored = decryptedBlock.map((b, idx) => b ^ prevBlock[idx]);

        Buffer.from(xored).copy(plainBytes, offset);
        prevBlock = cipherBlock;
    }

    return pkcs7Unpad(plainBytes).toString('utf8');
}

module.exports = {
    encrypt,
    decrypt,
    // diekspos untuk keperluan testing / laporan jika diperlukan
    _internal: {
        encryptBlock,
        decryptBlock,
        keyExpansion,
        SBOX,
        INV_SBOX
    }
};
