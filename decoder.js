"use strict";

/*
 * ============================================================
 * HYPERCRYPT
 * decoder.js
 *
 * Reverse encoding pipeline:
 *
 * Base64
 *    ↓
 * HyperPackage
 *    ↓
 * HyperMath reversal
 *    ↓
 * AES-256-GCM
 *    ↓
 * Original Message
 * ============================================================
 */


class HyperDecoder {


    // ========================================================
    // DECODE
    // ========================================================

    static async decode(encoded, password) {

        if (
            typeof encoded !== "string" ||
            encoded.trim().length === 0
        ) {

            throw new Error(
                "Encoded data is required."
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
        // BASE64 → JSON
        // ====================================================

        let packageJSON;


        try {

            const binary =
                atob(
                    encoded.trim()
                );


            packageJSON =
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

        } catch (error) {

            throw new Error(
                "Encoded data is not valid Base64."
            );

        }


        // ====================================================
        // STEP 2
        // JSON → HYPERCRYPT PACKAGE
        // ====================================================

        let packageData;


        try {

            packageData =
                HyperPackage.deserialize(
                    packageJSON
                );

        } catch (error) {

            throw new Error(
                "Invalid HyperCrypt package: " +
                error.message
            );

        }


        // ====================================================
        // STEP 3
        // CHECK HYPERMATH
        // ====================================================

        if (
            !packageData.hyperMath ||
            packageData.hyperMath.enabled !== true
        ) {

            throw new Error(
                "This package does not contain HyperMath data."
            );

        }


        if (
            packageData.hyperMath.version !==
            HyperMath.CONFIG.VERSION &&
            packageData.hyperMath.version !== 1
        ) {

            throw new Error(
                "Unsupported HyperMath version."
            );

        }


        // ====================================================
        // STEP 4
        // BASE64 → TRANSFORMED CIPHERTEXT
        // ====================================================

        let transformedCiphertext;


        try {

            transformedCiphertext =
                HyperCrypt.base64ToBytes(
                    packageData.ciphertext
                );

        } catch (error) {

            throw new Error(
                "Invalid ciphertext data."
            );

        }


        // ====================================================
        // STEP 5
        // REVERSE HYPERMATH
        // ====================================================

        let originalCiphertext;


        try {

            originalCiphertext =
                HyperMath.inverseTransform(
                    transformedCiphertext,
                    packageData.timestamp,
                    packageData.originalCiphertextLength
                );

        } catch (error) {

            throw new Error(
                "Could not reverse HyperMath: " +
                error.message
            );

        }


        // ====================================================
        // STEP 6
        // REBUILD CRYPT PACKAGE
        // ====================================================

        const cryptPackage = {

            ciphertext:
                HyperCrypt.bytesToBase64(
                    originalCiphertext
                ),

            timestamp:
                packageData.timestamp,

            salt:
                packageData.salt,

            iv:
                packageData.iv

        };


        // ====================================================
        // STEP 7
        // CONVERT BACK TO BASE64
        // ====================================================

        const cryptJSON =
            JSON.stringify(
                cryptPackage
            );


        const cryptEncoded =
            btoa(
                unescape(
                    encodeURIComponent(
                        cryptJSON
                    )
                )
            );


        // ====================================================
        // STEP 8
        // AES-256-GCM DECRYPTION
        // ====================================================

        let message;


        try {

            message =
                await HyperCrypt.decrypt(
                    cryptEncoded,
                    password
                );

        } catch (error) {

            throw new Error(
                "AES-256-GCM verification failed. " +
                "The password may be incorrect or the data may have been modified."
            );

        }


        return message;

    }


    // ========================================================
    // SELF TEST
    // ========================================================

    static async selfTest() {

        console.log(
            "HyperDecoder: starting test..."
        );


        const message =
            "HyperCrypt decoder test.";


        const password =
            "TestPassword-123";


        // ----------------------------------------------------
        // Encode
        // ----------------------------------------------------

        const encoded =
            await HyperEncoder.encode(
                message,
                password
            );


        // ----------------------------------------------------
        // Decode
        // ----------------------------------------------------

        const decoded =
            await HyperDecoder.decode(
                encoded,
                password
            );


        // ----------------------------------------------------
        // Compare
        // ----------------------------------------------------

        if (
            decoded !== message
        ) {

            throw new Error(
                "DECODER TEST FAILED: message mismatch."
            );

        }


        console.log(
            "Original:"
        );

        console.log(
            message
        );


        console.log(
            "Decoded:"
        );

        console.log(
            decoded
        );


        console.log(
            "HyperDecoder: TEST PASSED."
        );


        return true;

    }

}


// ============================================================
// GLOBAL ACCESS
// ============================================================

window.HyperDecoder =
    HyperDecoder;
