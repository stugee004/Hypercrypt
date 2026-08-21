```javascript
"use strict";

/*
 * ============================================================
 * HYPERCRYPT
 * encoder.js
 *
 * Combines:
 *
 *     crypt.js
 *        +
 *     hypermath.js
 *
 * into the first complete encoding pipeline.
 *
 * Pipeline:
 *
 * Message
 *    ↓
 * AES-256-GCM
 *    ↓
 * Encrypted bytes
 *    ↓
 * HyperMath
 *    ↓
 * Package
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
        // STEP 1
        // Encrypt the message using AES-256-GCM.
        //
        // crypt.js generates the timestamp internally.
        // ----------------------------------------------------

        const encrypted =
            await HyperCrypt.encrypt(
                message,
                password
            );


        // ----------------------------------------------------
        // STEP 2
        // Decode the crypt.js package.
        //
        // We need access to the timestamp and encrypted
        // ciphertext so HyperMath can process it.
        // ----------------------------------------------------

        let cryptPackage;

        try {

            const json =
                decodeURIComponent(
                    escape(
                        atob(encrypted)
                    )
                );

            cryptPackage =
                JSON.parse(json);

        } catch (error) {

            throw new Error(
                "Could not read encrypted package."
            );
        }


        // ----------------------------------------------------
        // STEP 3
        // Extract ciphertext.
        // ----------------------------------------------------

        const ciphertext =
            HyperCrypt.base64ToBytes(
                cryptPackage.ciphertext
            );


        // ----------------------------------------------------
        // STEP 4
        // Apply HyperMath.
        // ----------------------------------------------------

        const mathResult =
            HyperMath.transform(
                ciphertext,
                cryptPackage.timestamp
            );


        // ----------------------------------------------------
        // STEP 5
        // Replace the original ciphertext with the
        // mathematically transformed ciphertext.
        // ----------------------------------------------------

        cryptPackage.ciphertext =
            HyperCrypt.bytesToBase64(
                mathResult.data
            );


        // Store the original ciphertext length because
        // HyperMath pads data to multiples of four bytes.

        cryptPackage.originalCiphertextLength =
            mathResult.originalLength;


        // Record that HyperMath was applied.

        cryptPackage.hyperMath = {

            enabled: true,

            version: 1,

            rounds:
                HyperMath.CONFIG.ROUNDS
        };


        // ----------------------------------------------------
        // STEP 6
        // Convert final package to JSON.
        // ----------------------------------------------------

        const finalJSON =
            JSON.stringify(
                cryptPackage
            );


        // ----------------------------------------------------
        // STEP 7
        // Encode package as Base64.
        // ----------------------------------------------------

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
    // SIMPLE TEST
    // ========================================================

    static async selfTest() {

        const message =
            "HyperCrypt encoder test.";

        const password =
            "TestPassword-123";


        console.log(
            "HyperEncoder: starting test..."
        );


        const encoded =
            await HyperEncoder.encode(
                message,
                password
            );


        console.log(
            "HyperEncoder output:"
        );

        console.log(
            encoded
        );


        if (
            typeof encoded !== "string" ||
            encoded.length === 0
        ) {

            throw new Error(
                "ENCODER TEST FAILED."
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

window.HyperEncoder = HyperEncoder;
```
