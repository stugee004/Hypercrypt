"use strict";

/*
 * ============================================================
 * HYPERCRYPT
 * crypt.js — Core Cryptography Engine
 *
 * Version 1.1
 *
 * Security-critical encryption is handled by the browser's
 * Web Crypto API.
 *
 * Pipeline:
 *
 * Password
 *    ↓
 * PBKDF2-SHA256
 *    ↓
 * AES-256-GCM key
 *    ↓
 * AES-256-GCM
 *    ↓
 * Encrypted package
 *
 * HyperMath is applied separately by encoder.js.
 * ============================================================
 */


class HyperCrypt {


    // ========================================================
    // CONFIGURATION
    // ========================================================

    static CONFIG = {

        VERSION: 1,

        KEY_LENGTH: 256,

        PBKDF2_ITERATIONS: 600000,

        MIN_PBKDF2_ITERATIONS: 100000,

        MAX_PBKDF2_ITERATIONS: 2000000,

        HASH: "SHA-256",

        TAG_LENGTH: 128,

        SALT_LENGTH: 16,

        NONCE_LENGTH: 12

    };


    // ========================================================
    // RANDOM DATA
    // ========================================================

    static randomBytes(length) {

        if (
            !Number.isInteger(length) ||
            length <= 0
        ) {

            throw new Error(
                "Random byte length must be a positive integer."
            );

        }


        const bytes =
            new Uint8Array(length);


        crypto.getRandomValues(bytes);


        return bytes;

    }


    // ========================================================
    // BYTE / BASE64 CONVERSION
    // ========================================================

    static bytesToBase64(bytes) {

        if (!(bytes instanceof Uint8Array)) {

            throw new Error(
                "Expected Uint8Array."
            );

        }


        let binary = "";


        for (
            let i = 0;
            i < bytes.length;
            i++
        ) {

            binary +=
                String.fromCharCode(
                    bytes[i]
                );

        }


        return btoa(binary);

    }


    static base64ToBytes(base64) {

        if (
            typeof base64 !== "string"
        ) {

            throw new Error(
                "Base64 input must be a string."
            );

        }


        const binary =
            atob(base64);


        const bytes =
            new Uint8Array(
                binary.length
            );


        for (
            let i = 0;
            i < binary.length;
            i++
        ) {

            bytes[i] =
                binary.charCodeAt(i);

        }


        return bytes;

    }


    // ========================================================
    // ITERATION VALIDATION
    // ========================================================

    static validateIterations(iterations) {

        if (
            !Number.isInteger(iterations)
        ) {

            throw new Error(
                "PBKDF2 iteration count must be an integer."
            );

        }


        if (
            iterations <
            HyperCrypt.CONFIG.MIN_PBKDF2_ITERATIONS
        ) {

            throw new Error(
                "PBKDF2 iteration count is too low."
            );

        }


        if (
            iterations >
            HyperCrypt.CONFIG.MAX_PBKDF2_ITERATIONS
        ) {

            throw new Error(
                "PBKDF2 iteration count is too high."
            );

        }


        return iterations;

    }


    // ========================================================
    // PASSWORD → KEY
    // ========================================================

    static async deriveKey(
        password,
        salt,
        iterations =
            HyperCrypt.CONFIG.PBKDF2_ITERATIONS
    ) {

        if (
            typeof password !== "string"
        ) {

            throw new Error(
                "Password must be a string."
            );

        }


        if (
            password.length === 0
        ) {

            throw new Error(
                "Password cannot be empty."
            );

        }


        if (
            !(salt instanceof Uint8Array)
        ) {

            throw new Error(
                "Salt must be Uint8Array."
            );

        }


        if (
            salt.length !==
            HyperCrypt.CONFIG.SALT_LENGTH
        ) {

            throw new Error(
                "Invalid salt length."
            );

        }


        iterations =
            HyperCrypt.validateIterations(
                iterations
            );


        // ----------------------------------------------------
        // Convert password into key material
        // ----------------------------------------------------

        const passwordBytes =
            new TextEncoder().encode(
                password
            );


        const passwordKey =
            await crypto.subtle.importKey(

                "raw",

                passwordBytes,

                {
                    name: "PBKDF2"
                },

                false,

                ["deriveKey"]

            );


        // ----------------------------------------------------
        // Derive AES-256 key
        // ----------------------------------------------------

        return await crypto.subtle.deriveKey(

            {

                name: "PBKDF2",

                salt: salt,

                iterations: iterations,

                hash:
                    HyperCrypt.CONFIG.HASH

            },

            passwordKey,

            {

                name: "AES-GCM",

                length:
                    HyperCrypt.CONFIG.KEY_LENGTH

            },

            false,

            [
                "encrypt",
                "decrypt"
            ]

        );

    }


    // ========================================================
    // ENCRYPT
    // ========================================================

    static async encrypt(
        message,
        password
    ) {

        if (
            typeof message !== "string"
        ) {

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
        // 1. Generate random cryptographic values
        // ----------------------------------------------------

        const salt =
            HyperCrypt.randomBytes(
                HyperCrypt.CONFIG.SALT_LENGTH
            );


        const nonce =
            HyperCrypt.randomBytes(
                HyperCrypt.CONFIG.NONCE_LENGTH
            );


        // ----------------------------------------------------
        // 2. Timestamp
        // ----------------------------------------------------

        const timestamp =
            new Date().toISOString();


        // ----------------------------------------------------
        // 3. KDF parameters
        // ----------------------------------------------------

        const iterations =
            HyperCrypt.CONFIG.PBKDF2_ITERATIONS;


        // ----------------------------------------------------
        // 4. Derive AES key
        // ----------------------------------------------------

        const key =
            await HyperCrypt.deriveKey(

                password,

                salt,

                iterations

            );


        // ----------------------------------------------------
        // 5. Message → bytes
        // ----------------------------------------------------

        const messageBytes =
            new TextEncoder().encode(
                message
            );


        // ----------------------------------------------------
        // 6. AES-256-GCM
        // ----------------------------------------------------

        const encrypted =
            await crypto.subtle.encrypt(

                {

                    name: "AES-GCM",

                    iv: nonce,

                    tagLength:
                        HyperCrypt.CONFIG.TAG_LENGTH

                },

                key,

                messageBytes

            );


        // ----------------------------------------------------
        // 7. Package
        // ----------------------------------------------------

        const packageData = {

            version:
                HyperCrypt.CONFIG.VERSION,

            algorithm:
                "AES-256-GCM",

            keyDerivation:
                "PBKDF2-SHA256",

            iterations:
                iterations,

            timestamp:
                timestamp,

            salt:
                HyperCrypt.bytesToBase64(
                    salt
                ),

            nonce:
                HyperCrypt.bytesToBase64(
                    nonce
                ),

            ciphertext:
                HyperCrypt.bytesToBase64(
                    new Uint8Array(
                        encrypted
                    )
                )

        };


        // ----------------------------------------------------
        // 8. JSON → Base64
        // ----------------------------------------------------

        const json =
            JSON.stringify(
                packageData
            );


        return btoa(
            unescape(
                encodeURIComponent(
                    json
                )
            )
        );

    }


    // ========================================================
    // DECRYPT
    // ========================================================

    static async decrypt(
        encodedData,
        password
    ) {

        if (
            typeof encodedData !== "string"
        ) {

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
        // 1. Decode package
        // ----------------------------------------------------

        let packageData;


        try {

            const json =
                decodeURIComponent(
                    escape(
                        atob(
                            encodedData
                        )
                    )
                );


            packageData =
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
            !packageData ||
            !packageData.version ||
            !packageData.algorithm ||
            !packageData.keyDerivation ||
            !packageData.iterations ||
            !packageData.salt ||
            !packageData.nonce ||
            !packageData.ciphertext
        ) {

            throw new Error(
                "Invalid HyperCrypt package."
            );

        }


        if (
            packageData.version !==
            HyperCrypt.CONFIG.VERSION
        ) {

            throw new Error(
                "Unsupported HyperCrypt version."
            );

        }


        if (
            packageData.algorithm !==
            "AES-256-GCM"
        ) {

            throw new Error(
                "Unsupported encryption algorithm."
            );

        }


        if (
            packageData.keyDerivation !==
            "PBKDF2-SHA256"
        ) {

            throw new Error(
                "Unsupported key derivation method."
            );

        }


        const iterations =
            HyperCrypt.validateIterations(
                packageData.iterations
            );


        // ----------------------------------------------------
        // 3. Decode cryptographic values
        // ----------------------------------------------------

        const salt =
            HyperCrypt.base64ToBytes(
                packageData.salt
            );


        const nonce =
            HyperCrypt.base64ToBytes(
                packageData.nonce
            );


        const ciphertext =
            HyperCrypt.base64ToBytes(
                packageData.ciphertext
            );


        if (
            salt.length !==
            HyperCrypt.CONFIG.SALT_LENGTH
        ) {

            throw new Error(
                "Invalid salt length."
            );

        }


        if (
            nonce.length !==
            HyperCrypt.CONFIG.NONCE_LENGTH
        ) {

            throw new Error(
                "Invalid nonce length."
            );

        }


        // ----------------------------------------------------
        // 4. Recreate AES key using package KDF settings
        // ----------------------------------------------------

        const key =
            await HyperCrypt.deriveKey(

                password,

                salt,

                iterations

            );


        // ----------------------------------------------------
        // 5. AES-GCM decrypt
        // ----------------------------------------------------

        let decrypted;


        try {

            decrypted =
                await crypto.subtle.decrypt(

                    {

                        name: "AES-GCM",

                        iv: nonce,

                        tagLength:
                            HyperCrypt.CONFIG.TAG_LENGTH

                    },

                    key,

                    ciphertext

                );

        } catch (error) {

            throw new Error(
                "Decryption failed. The password may be incorrect, or the data may have been modified."
            );

        }


        // ----------------------------------------------------
        // 6. Bytes → text
        // ----------------------------------------------------

        return new TextDecoder().decode(
            decrypted
        );

    }


    // ========================================================
    // SELF TEST
    // ========================================================

    static async selfTest() {

        const message =
            "HyperCrypt test message.";


        const password =
            "TestPassword-123";


        console.log(
            "HyperCrypt: starting self-test..."
        );


        const encrypted =
            await HyperCrypt.encrypt(
                message,
                password
            );


        console.log(
            "Encrypted:",
            encrypted
        );


        const decrypted =
            await HyperCrypt.decrypt(
                encrypted,
                password
            );


        console.log(
            "Decrypted:",
            decrypted
        );


        if (
            decrypted !== message
        ) {

            throw new Error(
                "SELF-TEST FAILED."
            );

        }


        console.log(
            "HyperCrypt: SELF-TEST PASSED."
        );


        return true;

    }

}


// ============================================================
// GLOBAL ACCESS
// ============================================================

window.HyperCrypt =
    HyperCrypt;
