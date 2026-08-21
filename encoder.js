```javascript
"use strict";

/*
 * HYPERCRYPT
 * encoder.js
 *
 * Complete encoding pipeline:
 *
 * Message
 *    ↓
 * AES-256-GCM
 *    ↓
 * Encrypted bytes
 *    ↓
 * HyperMath
 *    ↓
 * Final package
 *    ↓
 * Base64
 */


class HyperEncoder {

    static async encode(message, password) {

        if (typeof message !== "string") {
            throw new Error("Message must be a string.");
        }

        if (
            typeof password !== "string" ||
            password.length === 0
        ) {
            throw new Error("A password is required.");
        }


        // ----------------------------------------------------
        // 1. Encrypt the message with AES-256-GCM
        // ----------------------------------------------------

        const encrypted =
            await HyperCrypt.encrypt(
                message,
                password
            );


        // ----------------------------------------------------
        // 2. Read the cryptographic package
        // ----------------------------------------------------

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


        // ----------------------------------------------------
        // 3. Extract ciphertext
        // ----------------------------------------------------

        const ciphertext =
            HyperCrypt.base64ToBytes(
                cryptPackage.ciphertext
            );


        // ----------------------------------------------------
        // 4. Apply HyperMath
        // ----------------------------------------------------

        const mathResult =
            HyperMath.transform(
                ciphertext,
                cryptPackage.timestamp
            );


        // ----------------------------------------------------
        // 5. Replace ciphertext with HyperMath output
        // ----------------------------------------------------

        cryptPackage.ciphertext =
            HyperCrypt.bytesToBase64(
                mathResult.data
            );


        cryptPackage.originalCiphertextLength =
            mathResult.originalLength;


        // ----------------------------------------------------
        // 6. Record HyperMath information
        // ----------------------------------------------------

        cryptPackage.hyperMath = {

            enabled: true,

            version: 1,

            rounds:
                HyperMath.CONFIG.ROUNDS
        };


        // ----------------------------------------------------
        // 7. Convert final package to JSON
        // ----------------------------------------------------

        const finalJSON =
            JSON.stringify(
                cryptPackage
            );


        // ----------------------------------------------------
        // 8. Convert final package to Base64
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
    // SELF TEST
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
