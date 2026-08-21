"use strict";

/*
 * ============================================================
 * HYPERCRYPT
 * package.js
 *
 * HyperCrypt Package Manager
 *
 * Responsible for:
 *
 *   • Creating standardized HyperCrypt packages
 *   • Validating packages
 *   • Identifying package versions
 *   • Storing algorithm information
 *   • Preparing packages for future upgrades
 *
 * IMPORTANT:
 *
 * This file does NOT perform encryption.
 *
 * AES-256-GCM remains responsible for encryption.
 * HyperMath remains responsible for mathematical transformation.
 *
 * package.js simply organizes the encrypted information.
 * ============================================================
 */


class HyperPackage {


    // ========================================================
    // PACKAGE INFORMATION
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
    // CREATE PACKAGE
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

            iv = null,

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
            typeof timestamp !== "number" &&
            typeof timestamp !== "string"
        ) {

            throw new Error(
                "Package requires a timestamp."
            );
        }


        const packageData = {

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

            hyperMath: {

                enabled:
                    hyperMath?.enabled === true,

                version:
                    hyperMath?.version ??
                    this.CONFIG.HYPERMATH_VERSION,

                rounds:
                    hyperMath?.rounds ??
                    0

            },

            timestamp:
                timestamp,

            salt:
                salt,

            iv:
                iv,

            ciphertext:
                ciphertext,

            originalCiphertextLength:
                originalCiphertextLength

        };


        return packageData;
    }


    // ========================================================
    // VALIDATE PACKAGE
    // ========================================================

    static validate(packageData) {

        const errors = [];


        // ----------------------------------------------------
        // Basic object check
        // ----------------------------------------------------

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


        // ----------------------------------------------------
        // Magic identifier
        // ----------------------------------------------------

        if (
            packageData.magic !==
            this.CONFIG.MAGIC
        ) {

            errors.push(
                "Invalid HyperCrypt package identifier."
            );

        }


        // ----------------------------------------------------
        // Protocol
        // ----------------------------------------------------

        if (
            packageData.protocol !==
            this.CONFIG.PROTOCOL
        ) {

            errors.push(
                "Unsupported HyperCrypt protocol."
            );

        }


        // ----------------------------------------------------
        // Version
        // ----------------------------------------------------

        if (
            packageData.version !==
            this.CONFIG.VERSION
        ) {

            errors.push(
                "Unsupported HyperCrypt package version."
            );

        }


        // ----------------------------------------------------
        // Encryption algorithm
        // ----------------------------------------------------

        if (
            packageData.algorithm !==
            this.CONFIG.ALGORITHM
        ) {

            errors.push(
                "Unsupported encryption algorithm."
            );

        }


        // ----------------------------------------------------
        // Key derivation
        // ----------------------------------------------------

        if (
            packageData.keyDerivation !==
            this.CONFIG.KEY_DERIVATION
        ) {

            errors.push(
                "Unsupported key derivation method."
            );

        }


        // ----------------------------------------------------
        // Ciphertext
        // ----------------------------------------------------

        if (
            typeof packageData.ciphertext !==
            "string" ||

            packageData.ciphertext.length === 0
        ) {

            errors.push(
                "Missing ciphertext."
            );

        }


        // ----------------------------------------------------
        // Timestamp
        // ----------------------------------------------------

        if (
            typeof packageData.timestamp !==
                "number" &&

            typeof packageData.timestamp !==
                "string"
        ) {

            errors.push(
                "Missing timestamp."
            );

        }


        // ----------------------------------------------------
        // HyperMath
        // ----------------------------------------------------

        if (
            typeof packageData.hyperMath !==
            "object" ||

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
            typeof serialized !==
            "string"
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
                typeof packageData?.ciphertext ===
                    "string"

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
    // PROTOCOL CHECK
    // ========================================================

    static isHyperCryptPackage(packageData) {

        return (
            typeof packageData ===
                "object" &&

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
                    Date.now(),

                salt:
                    "TEST-SALT",

                iv:
                    "TEST-IV",

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
            restored.version !==
            1
        ) {

            throw new Error(
                "PACKAGE TEST FAILED: version mismatch."
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
