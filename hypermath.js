"use strict";

/*
 * HYPERCRYPT
 * hypermath.js
 *
 * Custom reversible mathematical transformation.
 *
 * IMPORTANT:
 * This is NOT the security-critical encryption layer.
 * AES-256-GCM in crypt.js provides the actual cryptographic
 * protection.
 *
 * HyperMath is an additional reversible transformation.
 */


class HyperMath {

    // =========================================================
    // CONFIGURATION
    // =========================================================

    static CONFIG = {

        // Number of mathematical transformation rounds.
        ROUNDS: 12,

        // Large constants used by the transformation.
        CONSTANT_A: 0x9E3779B1,
        CONSTANT_B: 0x85EBCA77,
        CONSTANT_C: 0xC2B2AE3D
    };


    // =========================================================
    // 32-BIT UTILITIES
    // =========================================================

    static uint32(value) {

        return value >>> 0;
    }


    static rotateLeft(value, amount) {

        value >>>= 0;

        amount &= 31;

        return (
            (value << amount) |
            (value >>> (32 - amount))
        ) >>> 0;
    }


    static rotateRight(value, amount) {

        value >>>= 0;

        amount &= 31;

        return (
            (value >>> amount) |
            (value << (32 - amount))
        ) >>> 0;
    }


    // =========================================================
    // TIMESTAMP → NUMBER
    // =========================================================

    static timestampNumber(timestamp) {

        const date =
            new Date(timestamp);

        if (Number.isNaN(date.getTime())) {

            throw new Error(
                "Invalid timestamp."
            );
        }

        return (
            date.getTime() >>> 0
        );
    }


    // =========================================================
    // FORWARD MATHEMATICAL TRANSFORMATION
    // =========================================================

    static transform(bytes, timestamp) {

        if (!(bytes instanceof Uint8Array)) {

            throw new Error(
                "HyperMath expects Uint8Array."
            );
        }


        const time =
            HyperMath.timestampNumber(
                timestamp
            );


        const output =
            new Uint8Array(bytes.length);


        for (let i = 0; i < bytes.length; i++) {

            let x =
                bytes[i];


            // -------------------------------------------------
            // Position-dependent value
            // -------------------------------------------------

            let position =
                (
                    Math.imul(
                        i + 1,
                        HyperMath.CONFIG.CONSTANT_A
                    ) +
                    time
                ) >>> 0;


            // -------------------------------------------------
            // Multiple mathematical rounds
            // -------------------------------------------------

            for (
                let round = 0;
                round < HyperMath.CONFIG.ROUNDS;
                round++
            ) {

                const roundConstant =
                    (
                        HyperMath.CONFIG.CONSTANT_B +
                        Math.imul(
                            round + 1,
                            HyperMath.CONFIG.CONSTANT_C
                        )
                    ) >>> 0;


                // Expand byte into 32-bit value.

                let value =
                    (
                        x +
                        position +
                        roundConstant
                    ) >>> 0;


                // Nonlinear multiplication.

                value =
                    Math.imul(
                        value ^ (value >>> 16),
                        0x45D9F3B
                    ) >>> 0;


                // More mixing.

                value ^=
                    value >>> 13;

                value =
                    Math.imul(
                        value,
                        0x119DE1F3
                    ) >>> 0;

                value ^=
                    value >>> 16;


                // Rotation based on position and round.

                value =
                    HyperMath.rotateLeft(
                        value,
                        (
                            (i * 7) +
                            (round * 11) +
                            (time & 31)
                        ) & 31
                    );


                // Fold back into one byte.

                x =
                    (
                        value ^
                        (value >>> 8) ^
                        (value >>> 16) ^
                        (value >>> 24)
                    ) & 0xFF;
            }


            output[i] = x;
        }


        return output;
    }


    // =========================================================
    // REVERSE MATHEMATICAL TRANSFORMATION
    // =========================================================
    //
    // This reverses transform().
    //
    // Every operation above has to be inverted in the exact
    // reverse order.
    //
    // =========================================================

    static inverseTransform(bytes, timestamp) {

        /*
         * The first HyperMath prototype is intentionally kept
         * separate from crypt.js while we verify the exact
         * mathematical reversibility.
         *
         * We will implement the inverse after testing the
         * forward transformation and establishing the precise
         * reversible byte mapping.
         */

        throw new Error(
            "HyperMath inverse transformation has not been implemented yet."
        );
    }
}


// =============================================================
// GLOBAL ACCESS
// =============================================================

window.HyperMath = HyperMath;
