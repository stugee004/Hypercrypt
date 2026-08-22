"use strict";

/*
 * ============================================================
 * HYPERCRYPT
 * encoder.js
 *
 * Complete encoding pipeline:
 *
 * Message
 *    ↓
 * AES-256-GCM
 *    ↓
 * HyperMath
 *    ↓
 * HyperPackage
 *    ↓
 * Base64
 * ============================================================
 */


class HyperEncoder {


    // ========================================================
    // ENCODE
    // ========================================================

    static async encode(message, password) {

        if (typeof message !== "string") {

            throw new Error(
                "Message must be a string."
            );

        }


        if (
            typeof password !== "string" ||
            password.length === 0
        ) {

            throw new Error(
                "A password is required."
            );

        }


        // ----------------------------------------------------
        // Make sure required systems exist.
        // ----------------------------------------------------

        if (
            typeof HyperCrypt ===
            "undefined"
        ) {

            throw new Error(
                "HyperCrypt is not loaded."
            );

        }


        if (
            typeof HyperMath ===
            "undefined"
        ) {

            throw new Error(
                "HyperMath is not loaded."
            );

        }


        if (
            typeof HyperPackage ===
            "undefined"
        ) {

            throw new Error(
                "HyperPackage is not loaded."
            );

        }


        // ====================================================
        // STEP 1
        // AES-256-GCM
        // ====================================================

        const encrypted =
            await HyperCrypt.encrypt(
                message,
                password
            );


        // ====================================================
        // STEP 2
        // READ ORIGINAL CRYPT PACKAGE
        // ====================================================

        let cryptPackage;


        try {

            const binary =
                atob(encrypted);


            const json =
                decodeURIComponent(
                    Array.from(binary)
                        .map(
                            character =>
                                "%" +
                                character
                                    .charCodeAt(0)
                                    .toString(16)
                                    .padStart(2, "0")
                        )
                        .join("")
                );


            cryptPackage =
                JSON.parse(json);

        } catch (error) {

            throw new Error(
                "Could not read encrypted package."
            );

        }


        // ====================================================
        // STEP 3
        // EXTRACT CIPHERTEXT
        // ====================================================

        const ciphertext =
            HyperCrypt.base64ToBytes(
                cryptPackage.ciphertext
            );


        // ====================================================
        // STEP 4
        // HYPERMATH
        // ====================================================

        const mathResult =
            HyperMath.transform(
                ciphertext,
                cryptPackage.timestamp
            );


        // ====================================================
        // STEP 5
        // CREATE FORMAL HYPERCRYPT PACKAGE
        // ====================================================

        const finalPackage =
    HyperPackage.create({

        ...cryptPackage,

        ciphertext:
            HyperCrypt.bytesToBase64(
                mathResult.data
            ),

        originalCiphertextLength:
            mathResult.originalLength,

        hyperMath: {

            enabled:
                true,

            version:
                HyperMath.CONFIG.VERSION ??
                1,

            rounds:
                HyperMath.CONFIG.ROUNDS

        }

    });


        // ====================================================
        // STEP 6
        // SERIALIZE
        // ====================================================

        const finalJSON =
            HyperPackage.serialize(
                finalPackage
            );


        // ====================================================
        // STEP 7
        // BASE64
        // ====================================================

        const finalEncoded =
            btoa(
                unescape(
                    encodeURIComponent(
                        finalJSON
                    )
                )
            );


        return finalEncoded;

    }


    // ========================================================
    // SELF TEST
    // ========================================================

    static async selfTest() {

        console.log(
            "HyperEncoder: starting test..."
        );


        const message =
            "HyperCrypt encoder test.";


        const password =
            "TestPassword-123";


        const encoded =
            await HyperEncoder.encode(
                message,
                password
            );


        if (
            typeof encoded !==
                "string" ||

            encoded.length === 0
        ) {

            throw new Error(
                "ENCODER TEST FAILED."
            );

        }


        console.log(
            "HyperEncoder output:"
        );


        console.log(
            encoded
        );


        // ----------------------------------------------------
        // Inspect package
        // ----------------------------------------------------

        try {

            const binary =
                atob(encoded);


            const json =
                decodeURIComponent(
                    Array.from(binary)
                        .map(
                            character =>
                                "%" +
                                character
                                    .charCodeAt(0)
                                    .toString(16)
                                    .padStart(2, "0")
                        )
                        .join("")
                );


            const packageData =
                JSON.parse(json);


            const inspection =
                HyperPackage.inspect(
                    packageData
                );


            console.log(
                "HyperCrypt package:"
            );


            console.log(
                inspection
            );


            if (
                !inspection.valid
            ) {

                throw new Error(
                    "PACKAGE VALIDATION FAILED."
                );

            }

        } catch (error) {

            throw new Error(
                "ENCODER PACKAGE TEST FAILED: " +
                error.message
            );

        }


        console.log(
            "HyperEncoder: TEST PASSED."
        );


        return encoded;

    }

}


// ============================================================
// GLOBAL ACCESS
// ============================================================

window.HyperEncoder =
    HyperEncoder;
