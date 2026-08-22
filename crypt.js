/*
HYPERCRYPT
crypt.js — Core Cryptography Engine

Version 1.0

Security-critical encryption is handled by the browser's
Web Crypto API rather than a home-made encryption algorithm.

Pipeline:

Password
↓
PBKDF2
↓
AES-256-GCM key
↓
AES-256-GCM encryption
↓
Encrypted package

The HyperMath transformation will be added separately.
*/
"use strict";
class HyperCrypt {

// =========================================================
// CONFIGURATION
// =========================================================

static CONFIG = {

    // AES-256 = 256-bit encryption key
    KEY_LENGTH: 256,

    // PBKDF2 iteration count.
    // We can tune this later after testing performance.
    PBKDF2_ITERATIONS: 600000,

    // SHA-256 is used by PBKDF2.
    HASH: "SHA-256",

    // AES-GCM authentication tag length.
    TAG_LENGTH: 128,

    // Random salt length.
    SALT_LENGTH: 16,

    // AES-GCM nonce length.
    NONCE_LENGTH: 12
};


// =========================================================
// RANDOM DATA
// =========================================================

static randomBytes(length) {

    const bytes = new Uint8Array(length);

    crypto.getRandomValues(bytes);

    return bytes;
}


// =========================================================
// BYTE / BASE64 CONVERSION
// =========================================================

static bytesToBase64(bytes) {

    let binary = "";

    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}


static base64ToBytes(base64) {

    const binary = atob(base64);

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}


// =========================================================
// PASSWORD → KEY
// =========================================================

static async deriveKey(password, salt) {

    if (typeof password !== "string") {
        throw new Error("Password must be a string.");
    }

    if (!(salt instanceof Uint8Array)) {
        throw new Error("Salt must be Uint8Array.");
    }


    // Convert password into cryptographic key material.

    const passwordBytes =
        new TextEncoder().encode(password);


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


    // Derive the actual AES-256 key.

    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",

            salt: salt,

            iterations:
                HyperCrypt.CONFIG.PBKDF2_ITERATIONS,

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


// =========================================================
// ENCRYPT
// =========================================================

static async encrypt(message, password) {

    if (typeof message !== "string") {
        throw new Error("Message must be a string.");
    }

    if (typeof password !== "string" ||
        password.length === 0) {

        throw new Error("A password is required.");
    }


    // -----------------------------------------------------
    // 1. Generate random cryptographic values
    // -----------------------------------------------------

    const salt =
        HyperCrypt.randomBytes(
            HyperCrypt.CONFIG.SALT_LENGTH
        );


    const nonce =
        HyperCrypt.randomBytes(
            HyperCrypt.CONFIG.NONCE_LENGTH
        );


    // -----------------------------------------------------
    // 2. Record timestamp
    // -----------------------------------------------------

    const timestamp =
        new Date().toISOString();


    // -----------------------------------------------------
    // 3. Turn password into AES key
    // -----------------------------------------------------

    const key =
        await HyperCrypt.deriveKey(
            password,
            salt
        );


    // -----------------------------------------------------
    // 4. Convert message into bytes
    // -----------------------------------------------------

    const messageBytes =
        new TextEncoder().encode(message);


    // -----------------------------------------------------
    // 5. Encrypt using AES-256-GCM
    // -----------------------------------------------------

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


    // -----------------------------------------------------
    // 6. Package everything needed for decoding
    // -----------------------------------------------------

    const packageData = {

        version: 1,

        algorithm: "AES-256-GCM",

        keyDerivation: "PBKDF2-SHA256",

        iterations:
            HyperCrypt.CONFIG.PBKDF2_ITERATIONS,

        timestamp: timestamp,

        salt:
            HyperCrypt.bytesToBase64(salt),

        nonce:
            HyperCrypt.bytesToBase64(nonce),

        ciphertext:
            HyperCrypt.bytesToBase64(
                new Uint8Array(encrypted)
            )
    };


    // -----------------------------------------------------
    // 7. Convert package into a single string
    // -----------------------------------------------------

    const json =
        JSON.stringify(packageData);


    return btoa(
        unescape(
            encodeURIComponent(json)
        )
    );
}


// =========================================================
// DECRYPT
// =========================================================

static async decrypt(encodedData, password) {

    if (typeof encodedData !== "string") {
        throw new Error(
            "Encoded data must be a string."
        );
    }

    if (typeof password !== "string" ||
        password.length === 0) {

        throw new Error(
            "A password is required."
        );
    }


    // -----------------------------------------------------
    // 1. Decode package
    // -----------------------------------------------------

    let packageData;

    try {

        const json =
            decodeURIComponent(
                escape(
                    atob(encodedData)
                )
            );

        packageData =
            JSON.parse(json);

    } catch (error) {

        throw new Error(
            "The encoded data is invalid or corrupted."
        );
    }


    // -----------------------------------------------------
    // 2. Verify package format
    // -----------------------------------------------------

    if (!packageData.version ||
        !packageData.algorithm ||
        !packageData.salt ||
        !packageData.nonce ||
        !packageData.ciphertext) {

        throw new Error(
            "Invalid HyperCrypt package."
        );
    }


    if (packageData.algorithm !== "AES-256-GCM") {

        throw new Error(
            "Unsupported encryption algorithm."
        );
    }


    // -----------------------------------------------------
    // 3. Decode cryptographic values
    // -----------------------------------------------------

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


    // -----------------------------------------------------
    // 4. Recreate AES key
    // -----------------------------------------------------

    const key =
        await HyperCrypt.deriveKey(
            password,
            salt
        );


    // -----------------------------------------------------
    // 5. Decrypt
    // -----------------------------------------------------

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


    // -----------------------------------------------------
    // 6. Convert bytes back to text
    // -----------------------------------------------------

    return new TextDecoder().decode(
        decrypted
    );
}


// =========================================================
// TEST
// =========================================================

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


    if (decrypted !== message) {

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
// =============================================================
// OPTIONAL GLOBAL ACCESS
// =============================================================
//
// This makes HyperCrypt available from the browser console:
//
// HyperCrypt.encrypt(...)
// HyperCrypt.decrypt(...)
// HyperCrypt.selfTest()
//
// =============================================================

window.HyperCrypt = HyperCrypt;

