"use strict";

/*
 * HYPERCRYPT
 * decoder.js
 *
 * Reverse encoding pipeline:
 *
 * Base64 package
 *      ↓
 * Package
 *      ↓
 * Reverse HyperMath
 *      ↓
 * AES-256-GCM
 *      ↓
 * Original message
 */


class HyperDecoder {


    // ========================================================
    // DECODE
    // ========================================================

    static async decode(encodedData, password) {

        if (typeof encodedData !== "string") {

            throw new Error(
                "Encoded data must be a string."
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
        // 1. Decode the outer Base64 package
        // ----------------------------------------------------

        let cryptPackage;

        try {

            const binary =
                atob(encodedData);


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
                "The encoded data is invalid or corrupted."
            );
        }


        // ----------------------------------------------------
        // 2. Validate package
        // ----------------------------------------------------

        if (
            !cryptPackage.version ||
            !cryptPackage.algorithm ||
            !cryptPackage.timestamp ||
            !cryptPackage.salt ||
            !cryptPackage.nonce ||
            !cryptPackage.ciphertext
        ) {

            throw new Error(
                "Invalid HyperCrypt package."
            );
        }


        if (
            cryptPackage.algorithm !==
            "AES-256-GCM"
        ) {

            throw new Error(
                "Unsupported encryption algorithm."
            );
        }


        if (
            !cryptPackage.hyperMath ||
            !cryptPackage.hyperMath.enabled
        ) {

            throw new Error(
                "HyperMath information is missing."
            );
        }


        // ----------------------------------------------------
        // 3. Decode the transformed ciphertext
        // ----------------------------------------------------

        const transformedCiphertext =
            HyperCrypt.base64ToBytes(
                cryptPackage.ciphertext
            );


        // ----------------------------------------------------
        // 4. Reverse HyperMath
        // ----------------------------------------------------

        const originalLength =
            cryptPackage.originalCiphertextLength;


        const ciphertext =
            HyperMath.inverseTransform(
                transformedCiphertext,
                cryptPackage.timestamp,
                originalLength
            );


        // ----------------------------------------------------
        // 5. Put the original ciphertext back into the
        // cryptographic package.
        // ----------------------------------------------------

        cryptPackage.ciphertext =
            HyperCrypt.bytesToBase64(
                ciphertext
            );


        // ----------------------------------------------------
        // 6. Recreate the package expected by crypt.js
        // ----------------------------------------------------

        const originalPackage = {

            version:
                cryptPackage.version,

            algorithm:
                cryptPackage.algorithm,

            keyDerivation:
                cryptPackage.keyDerivation,

            iterations:
                cryptPackage.iterations,

            timestamp:
                cryptPackage.timestamp,

            salt:
                cryptPackage.salt,

            nonce:
                cryptPackage.nonce,

            ciphertext:
                cryptPackage.ciphertext
        };


        // ----------------------------------------------------
        // 7. Convert package back into Base64
        // ----------------------------------------------------

        const packageJSON =
            JSON.stringify(
                originalPackage
            );


        const packageBase64 =
            btoa(
                unescape(
                    encodeURIComponent(
                        packageJSON
                    )
                )
            );


        // ----------------------------------------------------
        // 8. Let crypt.js perform AES-256-GCM decryption
        // ----------------------------------------------------

        const message =
            await HyperCrypt.decrypt(
                packageBase64,
                password
            );


        return message;
    }


    // ========================================================
    // FULL ROUND-TRIP TEST
    // ========================================================

    static async selfTest() {

        const originalMessage =
            "HyperCrypt round-trip test!";

        const password =
            "TestPassword-123";


        console.log(
            "HyperDecoder: starting full test..."
        );


        // ----------------------------------------------------
        // Encode
        // ----------------------------------------------------

        const encoded =
            await HyperEncoder.encode(
                originalMessage,
                password
            );


        console.log(
            "Encoded data:"
        );

        console.log(
            encoded
        );


        // ----------------------------------------------------
        // Decode
        // ----------------------------------------------------

        const decoded =
            await HyperDecoder.decode(
                encoded,
                password
            );


        console.log(
            "Decoded message:"
        );

        console.log(
            decoded
        );


        // ----------------------------------------------------
        // Verify
        // ----------------------------------------------------

        if (
            decoded !==
            originalMessage
        ) {

            throw new Error(
                "ROUND-TRIP TEST FAILED."
            );
        }


        console.log(
            "HyperCrypt: FULL ROUND-TRIP TEST PASSED!"
        );


        return decoded;
    }
}


// ============================================================
// GLOBAL ACCESS
// ============================================================

window.HyperDecoder = HyperDecoder;
