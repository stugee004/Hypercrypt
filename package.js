"use strict";

/*
 * ============================================================
 * HYPERCRYPT
 * package.js
 *
 * Formal HyperCrypt package manager.
 *
 * IMPORTANT:
 * The cryptographic package uses:
 *
 *     salt
 *     nonce
 *     ciphertext
 *
 * "nonce" must not be renamed to "iv" because crypt.js
 * expects the field to be called nonce.
 * ============================================================
 */


class HyperPackage {


    // ========================================================
    // CONFIGURATION
    // ========================================================

    static CONFIG = {

        MAGIC:
            "HYPERCRYPT",

        VERSION:
            1,

        PROTOCOL:
            "HYPERCRYPT-1",

        ALGORITHM:
            "AES-256-GCM",

        KEY_DERIVATION:
            "PBKDF2-SHA256",

        HYPERMATH_VERSION:
            1

    };


    // ========================================================
    // CREATE
    // ========================================================

    static create(options = {}) {

        if (
            typeof options !== "object" ||
            options === null
        ) {

            throw new Error(
                "Package options must be an object."
            );

        }


        const {

            ciphertext = null,

            timestamp = null,

            salt = null,

            nonce = null,

            originalCiphertextLength = null,

            hyperMath = null

        } = options;


        if (
            typeof ciphertext !== "string" ||
            ciphertext.length === 0
        ) {

            throw new Error(
                "Package requires ciphertext."
            );

        }


        if (
            typeof timestamp !== "string" &&
            typeof timestamp !== "number"
        ) {

            throw new Error(
                "Package requires a timestamp."
            );

        }


        if (
            typeof salt !== "string" ||
            salt.length === 0
        ) {

            throw new Error(
                "Package requires salt."
            );

        }


        if (
            typeof nonce !== "string" ||
            nonce.length === 0
        ) {

            throw new Error(
                "Package requires nonce."
            );

        }


        return {

            magic:
                this.CONFIG.MAGIC,

            protocol:
                this.CONFIG.PROTOCOL,

            version:
                this.CONFIG.VERSION,

            algorithm:
                this.CONFIG.ALGORITHM,

            keyDerivation:
                this.CONFIG.KEY_DERIVATION,

            timestamp:
                timestamp,

            salt:
                salt,

            nonce:
                nonce,

            ciphertext:
                ciphertext,

            originalCiphertextLength:
                originalCiphertextLength,

            hyperMath: {

                enabled:
                    hyperMath?.enabled === true,

                version:
                    hyperMath?.version ??
                    this.CONFIG.HYPERMATH_VERSION,

                rounds:
                    hyperMath?.rounds ??
                    0

            }

        };

    }


    // ========================================================
    // VALIDATE
    // ========================================================

    static validate(packageData) {

        const errors = [];


        if (
            typeof packageData !== "object" ||
            packageData === null
        ) {

            return {

                valid: false,

                errors: [
                    "Package is not an object."
                ]

            };

        }


        if (
            packageData.magic !==
            this.CONFIG.MAGIC
        ) {

            errors.push(
                "Invalid HyperCrypt package identifier."
            );

        }


        if (
            packageData.protocol !==
            this.CONFIG.PROTOCOL
        ) {

            errors.push(
                "Unsupported HyperCrypt protocol."
            );

        }


        if (
            packageData.version !==
            this.CONFIG.VERSION
        ) {

            errors.push(
                "Unsupported HyperCrypt package version."
            );

        }


        if (
            packageData.algorithm !==
            this.CONFIG.ALGORITHM
        ) {

            errors.push(
                "Unsupported encryption algorithm."
            );

        }


        if (
            packageData.keyDerivation !==
            this.CONFIG.KEY_DERIVATION
        ) {

            errors.push(
                "Unsupported key derivation method."
            );

        }


        if (
            typeof packageData.salt !== "string" ||
            packageData.salt.length === 0
        ) {

            errors.push(
                "Missing salt."
            );

        }


        if (
            typeof packageData.nonce !== "string" ||
            packageData.nonce.length === 0
        ) {

            errors.push(
                "Missing nonce."
            );

        }


        if (
            typeof packageData.ciphertext !== "string" ||
            packageData.ciphertext.length === 0
        ) {

            errors.push(
                "Missing ciphertext."
            );

        }


        if (
            typeof packageData.timestamp !== "string" &&
            typeof packageData.timestamp !== "number"
        ) {

            errors.push(
                "Missing timestamp."
            );

        }


        if (
            typeof packageData.hyperMath !== "object" ||
            packageData.hyperMath === null
        ) {

            errors.push(
                "Missing HyperMath information."
            );

        }


        return {

            valid:
                errors.length === 0,

            errors:
                errors

        };

    }


    // ========================================================
    // SERIALIZE
    // ========================================================

    static serialize(packageData) {

        const validation =
            this.validate(
                packageData
            );


        if (!validation.valid) {

            throw new Error(
                "Cannot serialize invalid package: " +
                validation.errors.join("; ")
            );

        }


        return JSON.stringify(
            packageData
        );

    }


    // ========================================================
    // DESERIALIZE
    // ========================================================

    static deserialize(serialized) {

        if (
            typeof serialized !== "string"
        ) {

            throw new Error(
                "Serialized package must be a string."
            );

        }


        let packageData;


        try {

            packageData =
                JSON.parse(
                    serialized
                );

        } catch (error) {

            throw new Error(
                "Invalid HyperCrypt package JSON."
            );

        }


        const validation =
            this.validate(
                packageData
            );


        if (!validation.valid) {

            throw new Error(
                "Invalid HyperCrypt package: " +
                validation.errors.join("; ")
            );

        }


        return packageData;

    }


    // ========================================================
    // INSPECT
    // ========================================================

    static inspect(packageData) {

        const validation =
            this.validate(
                packageData
            );


        return {

            valid:
                validation.valid,

            errors:
                validation.errors,

            magic:
                packageData?.magic ?? null,

            protocol:
                packageData?.protocol ?? null,

            version:
                packageData?.version ?? null,

            algorithm:
                packageData?.algorithm ?? null,

            keyDerivation:
                packageData?.keyDerivation ?? null,

            hyperMathVersion:
                packageData?.hyperMath?.version ??
                null,

            hyperMathRounds:
                packageData?.hyperMath?.rounds ??
                null,

            timestamp:
                packageData?.timestamp ??
                null,

            ciphertextLength:
                typeof packageData?.ciphertext === "string"
                    ? packageData.ciphertext.length
                    : 0

        };

    }


    // ========================================================
    // VERSION CHECK
    // ========================================================

    static supportsVersion(version) {

        return (
            version ===
            this.CONFIG.VERSION
        );

    }


    // ========================================================
    // PACKAGE IDENTIFICATION
    // ========================================================

    static isHyperCryptPackage(packageData) {

        return (
            typeof packageData === "object" &&
            packageData !== null &&
            packageData.magic ===
                this.CONFIG.MAGIC
        );

    }


    // ========================================================
    // SELF TEST
    // ========================================================

    static selfTest() {

        console.log(
            "HyperPackage: starting test..."
        );


        const testPackage =
            this.create({

                ciphertext:
                    "TEST-CIPHERTEXT",

                timestamp:
                    new Date().toISOString(),

                salt:
                    "TEST-SALT",

                nonce:
                    "TEST-NONCE",

                originalCiphertextLength:
                    16,

                hyperMath: {

                    enabled:
                        true,

                    version:
                        1,

                    rounds:
                        16

                }

            });


        const validation =
            this.validate(
                testPackage
            );


        if (!validation.valid) {

            throw new Error(
                "PACKAGE TEST FAILED: " +
                validation.errors.join("; ")
            );

        }


        const serialized =
            this.serialize(
                testPackage
            );


        const restored =
            this.deserialize(
                serialized
            );


        if (
            restored.magic !==
            "HYPERCRYPT"
        ) {

            throw new Error(
                "PACKAGE TEST FAILED: magic mismatch."
            );

        }


        if (
            restored.nonce !==
            "TEST-NONCE"
        ) {

            throw new Error(
                "PACKAGE TEST FAILED: nonce mismatch."
            );

        }


        console.log(
            "HyperPackage: TEST PASSED."
        );


        return true;

    }

}


// ============================================================
// GLOBAL ACCESS
// ============================================================

window.HyperPackage =
    HyperPackage;
