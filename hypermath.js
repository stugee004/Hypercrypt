"use strict";

/*
 * ============================================================
 * HYPERCRYPT
 * hypermath.js
 *
 * Reversible mathematical transformation layer.
 *
 * IMPORTANT:
 * This is NOT the primary encryption algorithm.
 *
 * AES-256-GCM in crypt.js provides the cryptographic security.
 *
 * HyperMath adds a reversible mathematical transformation
 * around the encrypted data.
 * ============================================================
 */


class HyperMath {

    // ========================================================
    // CONFIGURATION
    // ========================================================

    static CONFIG = {

        ROUNDS: 16,

        CONSTANT_A: 0x9E3779B9,

        CONSTANT_B: 0x85EBCA77,

        CONSTANT_C: 0xC2B2AE3D
    };


    // ========================================================
    // BASIC 32-BIT OPERATIONS
    // ========================================================

    static uint32(value) {

        return value >>> 0;
    }


    static rotateLeft(value, amount) {

        value >>>= 0;

        amount &= 31;

        if (amount === 0) {
            return value;
        }

        return (
            (value << amount) |
            (value >>> (32 - amount))
        ) >>> 0;
    }


    static rotateRight(value, amount) {

        value >>>= 0;

        amount &= 31;

        if (amount === 0) {
            return value;
        }

        return (
            (value >>> amount) |
            (value << (32 - amount))
        ) >>> 0;
    }


    // ========================================================
    // MODULAR MULTIPLICATION
    // ========================================================

    static multiply(value, constant) {

        return Math.imul(
            value >>> 0,
            constant >>> 0
        ) >>> 0;
    }


    // ========================================================
    // MODULAR MULTIPLICATIVE INVERSE
    // ========================================================
    //
    // We need this because:
    //
    //     y = x * constant
    //
    // can be reversed with:
    //
    //     x = y * inverse(constant)
    //
    // modulo 2^32.
    //
    // The constants must be ODD.
    // ========================================================

    static modInverse32(a) {

        a >>>= 0;

        if ((a & 1) === 0) {

            throw new Error(
                "Modular inverse requires an odd number."
            );
        }


        let x = a;


        // Newton-Raphson iteration modulo 2^32.

        for (let i = 0; i < 5; i++) {

            x =
                Math.imul(
                    x,
                    (
                        2 -
                        Math.imul(a, x)
                    )
                ) >>> 0;
        }


        return x >>> 0;
    }


    // ========================================================
    // MIX FUNCTION
    // ========================================================
    //
    // Every operation here is reversible.
    // ========================================================

    static mix(value, key, position, round) {

        value >>>= 0;
        key >>>= 0;


        // ----------------------------------------------------
        // Addition
        // ----------------------------------------------------

        value =
            (
                value +
                key +
                HyperMath.CONFIG.CONSTANT_A +
                position
            ) >>> 0;


        // ----------------------------------------------------
        // XOR
        // ----------------------------------------------------

        value ^=
            HyperMath.CONFIG.CONSTANT_B;


        // ----------------------------------------------------
        // Rotation
        // ----------------------------------------------------

        const rotation =
            (
                position +
                round * 7 +
                (key & 31)
            ) & 31;

        value =
            HyperMath.rotateLeft(
                value,
                rotation
            );


        // ----------------------------------------------------
        // Multiplication by odd number
        // ----------------------------------------------------

        value =
            HyperMath.multiply(
                value,
                0x45D9F3B
            );


        return value >>> 0;
    }


    // ========================================================
    // INVERSE MIX
    // ========================================================

    static inverseMix(value, key, position, round) {

        value >>>= 0;
        key >>>= 0;


        // ----------------------------------------------------
        // Reverse multiplication
        // ----------------------------------------------------

        const inverse =
            HyperMath.modInverse32(
                0x45D9F3B
            );


        value =
            HyperMath.multiply(
                value,
                inverse
            );


        // ----------------------------------------------------
        // Reverse rotation
        // ----------------------------------------------------

        const rotation =
            (
                position +
                round * 7 +
                (key & 31)
            ) & 31;

        value =
            HyperMath.rotateRight(
                value,
                rotation
            );


        // ----------------------------------------------------
        // Reverse XOR
        // ----------------------------------------------------

        value ^=
            HyperMath.CONFIG.CONSTANT_B;


        // ----------------------------------------------------
        // Reverse addition
        // ----------------------------------------------------

        value =
            (
                value -
                key -
                HyperMath.CONFIG.CONSTANT_A -
                position
            ) >>> 0;


        return value >>> 0;
    }


    // ========================================================
    // BUILD 32-BIT WORD FROM FOUR BYTES
    // ========================================================

    static bytesToWord(bytes, offset) {

        return (
            bytes[offset] |
            (bytes[offset + 1] << 8) |
            (bytes[offset + 2] << 16) |
            (bytes[offset + 3] << 24)
        ) >>> 0;
    }


    // ========================================================
    // WRITE 32-BIT WORD INTO FOUR BYTES
    // ========================================================

    static wordToBytes(word, bytes, offset) {

        bytes[offset] =
            word & 0xFF;

        bytes[offset + 1] =
            (word >>> 8) & 0xFF;

        bytes[offset + 2] =
            (word >>> 16) & 0xFF;

        bytes[offset + 3] =
            (word >>> 24) & 0xFF;
    }


    // ========================================================
    // TIMESTAMP → 32-BIT VALUE
    // ========================================================

    static timestampNumber(timestamp) {

        const time =
            new Date(timestamp).getTime();


        if (!Number.isFinite(time)) {

            throw new Error(
                "Invalid timestamp."
            );
        }


        return time >>> 0;
    }


    // ========================================================
    // DERIVE HYPERMATH KEY
    // ========================================================

    static deriveMathKey(timestamp) {

        let value =
            HyperMath.timestampNumber(
                timestamp
            );


        value ^=
            HyperMath.CONFIG.CONSTANT_A;


        value =
            HyperMath.multiply(
                value,
                HyperMath.CONFIG.CONSTANT_C
            );


        value =
            HyperMath.rotateLeft(
                value,
                13
            );


        value ^=
            value >>> 16;


        return value >>> 0;
    }


    // ========================================================
    // TRANSFORM
    // ========================================================

    static transform(bytes, timestamp) {

        if (!(bytes instanceof Uint8Array)) {

            throw new Error(
                "HyperMath expects Uint8Array."
            );
        }


        const mathKey =
            HyperMath.deriveMathKey(
                timestamp
            );


        // ----------------------------------------------------
        // Pad to a multiple of 4 bytes.
        // ----------------------------------------------------

        const originalLength =
            bytes.length;


        const paddedLength =
            Math.ceil(
                originalLength / 4
            ) * 4;


        const working =
            new Uint8Array(
                paddedLength
            );


        working.set(bytes);


        // ----------------------------------------------------
        // Process every 32-bit word.
        // ----------------------------------------------------

        for (
            let offset = 0;
            offset < working.length;
            offset += 4
        ) {

            let word =
                HyperMath.bytesToWord(
                    working,
                    offset
                );


            const position =
                offset / 4;


            // Position-dependent key.

            let key =
                (
                    mathKey +
                    Math.imul(
                        position + 1,
                        HyperMath.CONFIG.CONSTANT_B
                    )
                ) >>> 0;


            // Multiple reversible rounds.

            for (
                let round = 0;
                round < HyperMath.CONFIG.ROUNDS;
                round++
            ) {

                word =
                    HyperMath.mix(
                        word,
                        key,
                        position,
                        round
                    );


                // Change key for next round.

                key =
                    (
                        HyperMath.rotateLeft(
                            key,
                            5
                        ) +
                        HyperMath.CONFIG.CONSTANT_C
                    ) >>> 0;
            }


            HyperMath.wordToBytes(
                word,
                working,
                offset
            );
        }


        return {

            data: working,

            originalLength: originalLength
        };
    }


    // ========================================================
    // INVERSE TRANSFORM
    // ========================================================

    static inverseTransform(
        bytes,
        timestamp,
        originalLength
    ) {

        if (!(bytes instanceof Uint8Array)) {

            throw new Error(
                "HyperMath expects Uint8Array."
            );
        }


        const working =
            new Uint8Array(bytes);


        const mathKey =
            HyperMath.deriveMathKey(
                timestamp
            );


        // ----------------------------------------------------
        // Process words in the exact reverse order.
        // ----------------------------------------------------

        for (
            let offset = 0;
            offset < working.length;
            offset += 4
        ) {

            let word =
                HyperMath.bytesToWord(
                    working,
                    offset
                );


            const position =
                offset / 4;


            // Recreate the key used during encryption.

            const roundKeys =
                new Array(
                    HyperMath.CONFIG.ROUNDS
                );


            let key =
                (
                    mathKey +
                    Math.imul(
                        position + 1,
                        HyperMath.CONFIG.CONSTANT_B
                    )
                ) >>> 0;


            for (
                let round = 0;
                round < HyperMath.CONFIG.ROUNDS;
                round++
            ) {

                roundKeys[round] =
                    key;


                key =
                    (
                        HyperMath.rotateLeft(
                            key,
                            5
                        ) +
                        HyperMath.CONFIG.CONSTANT_C
                    ) >>> 0;
            }


            // Undo rounds backwards.

            for (
                let round =
                    HyperMath.CONFIG.ROUNDS - 1;

                round >= 0;

                round--
            ) {

                word =
                    HyperMath.inverseMix(
                        word,
                        roundKeys[round],
                        position,
                        round
                    );
            }


            HyperMath.wordToBytes(
                word,
                working,
                offset
            );
        }


        // ----------------------------------------------------
        // Remove padding.
        // ----------------------------------------------------

        if (
            typeof originalLength === "number" &&
            originalLength >= 0 &&
            originalLength <= working.length
        ) {

            return working.slice(
                0,
                originalLength
            );
        }


        return working;
    }


    // ========================================================
    // SELF TEST
    // ========================================================

    static selfTest() {

        const timestamp =
            new Date().toISOString();


        const original =
            new TextEncoder().encode(
                "HyperCrypt mathematical test!"
            );


        console.log(
            "HyperMath: original:",
            original
        );


        const transformed =
            HyperMath.transform(
                original,
                timestamp
            );


        console.log(
            "HyperMath: transformed:",
            transformed.data
        );


        const restored =
            HyperMath.inverseTransform(
                transformed.data,
                timestamp,
                transformed.originalLength
            );


        console.log(
            "HyperMath: restored:",
            restored
        );


        const originalText =
            new TextDecoder().decode(
                original
            );


        const restoredText =
            new TextDecoder().decode(
                restored
            );


        if (
            originalText !==
            restoredText
        ) {

            throw new Error(
                "HYPERMATH SELF-TEST FAILED."
            );
        }


        console.log(
            "HyperMath: SELF-TEST PASSED."
        );


        return true;
    }
}


// ============================================================
// GLOBAL ACCESS
// ============================================================

window.HyperMath = HyperMath;
