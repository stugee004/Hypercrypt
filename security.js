"use strict";

/*
 * ============================================================
 * HYPERCRYPT
 * security.js
 *
 * Security diagnostics for the HyperCrypt prototype.
 *
 * Tests:
 *
 * 1. Normal round trip
 * 2. Wrong password rejection
 * 3. Tamper detection
 * 4. Multiple independent encryptions
 *
 * These tests do NOT prove that HyperCrypt is secure.
 * They verify that important expected behaviors work.
 * ============================================================
 */


class HyperSecurity {


    // ========================================================
    // TEST 1
    // NORMAL ROUND TRIP
    // ========================================================

    static async testRoundTrip() {

        const message =
            "HyperCrypt security test.";

        const password =
            "HyperCrypt-Test-Password";


        const encoded =
            await HyperEncoder.encode(
                message,
                password
            );


        const decoded =
            await HyperDecoder.decode(
                encoded,
                password
            );


        return decoded === message;
    }


    // ========================================================
    // TEST 2
    // WRONG PASSWORD
    // ========================================================

    static async testWrongPassword() {

        const message =
            "Password verification test.";

        const correctPassword =
            "Correct-Password-123";

        const wrongPassword =
            "Wrong-Password-456";


        const encoded =
            await HyperEncoder.encode(
                message,
                correctPassword
            );


        try {

            await HyperDecoder.decode(
                encoded,
                wrongPassword
            );


            /*
             * If decoding succeeded with the wrong password,
             * something is wrong.
             */

            return false;

        } catch (error) {

            /*
             * AES-GCM should reject the authentication check.
             */

            return true;
        }
    }


    // ========================================================
    // TEST 3
    // TAMPER DETECTION
    // ========================================================

    static async testTamperDetection() {

        const message =
            "Tamper detection test.";

        const password =
            "Tamper-Test-Password";


        const encoded =
            await HyperEncoder.encode(
                message,
                password
            );


        /*
         * Change one character of the encoded package.
         *
         * This should cause authentication to fail.
         */

        const position =
            Math.floor(
                encoded.length / 2
            );


        const originalCharacter =
            encoded[position];


        const replacementCharacter =
            originalCharacter === "A"
                ? "B"
                : "A";


        const tampered =
            encoded.substring(
                0,
                position
            ) +
            replacementCharacter +
            encoded.substring(
                position + 1
            );


        try {

            await HyperDecoder.decode(
                tampered,
                password
            );


            /*
             * If the modified package successfully
             * decrypted, tamper detection failed.
             */

            return false;

        } catch (error) {

            return true;
        }
    }


    // ========================================================
    // TEST 4
    // INDEPENDENT ENCRYPTIONS
    // ========================================================

    static async testRandomization() {

        const message =
            "Randomization test.";

        const password =
            "Randomization-Password";


        const first =
            await HyperEncoder.encode(
                message,
                password
            );


        const second =
            await HyperEncoder.encode(
                message,
                password
            );


        /*
         * Two encryptions of the same message with the same
         * password should normally produce different output
         * because fresh cryptographic parameters are used.
         */

        return first !== second;
    }


    // ========================================================
    // RUN EVERYTHING
    // ========================================================

    static async runAll() {

        const results = {

            roundTrip: false,

            wrongPassword: false,

            tamperDetection: false,

            randomization: false

        };


        console.log(
            "HyperSecurity: starting diagnostics..."
        );


        // ----------------------------------------------------
        // Round trip
        // ----------------------------------------------------

        try {

            results.roundTrip =
                await HyperSecurity.testRoundTrip();

        } catch (error) {

            console.error(
                "Round-trip test failed:",
                error
            );

        }


        // ----------------------------------------------------
        // Wrong password
        // ----------------------------------------------------

        try {

            results.wrongPassword =
                await HyperSecurity.testWrongPassword();

        } catch (error) {

            console.error(
                "Wrong-password test failed:",
                error
            );

        }


        // ----------------------------------------------------
        // Tamper detection
        // ----------------------------------------------------

        try {

            results.tamperDetection =
                await HyperSecurity.testTamperDetection();

        } catch (error) {

            console.error(
                "Tamper test failed:",
                error
            );

        }


        // ----------------------------------------------------
        // Randomization
        // ----------------------------------------------------

        try {

            results.randomization =
                await HyperSecurity.testRandomization();

        } catch (error) {

            console.error(
                "Randomization test failed:",
                error
            );

        }


        console.log(
            "HyperSecurity diagnostics:",
            results
        );


        return results;
    }
}


// ============================================================
// GLOBAL ACCESS
// ============================================================

window.HyperSecurity =
    HyperSecurity;
