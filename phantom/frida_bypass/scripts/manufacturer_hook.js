/**
 * ORACLE-TMF · phantom/frida_bypass/scripts/manufacturer_hook.js
 * ================================================================
 * Frida hook: Spoof android.os.Build fields to return target device values.
 *
 * Malware uses Build.MANUFACTURER, Build.MODEL, Build.FINGERPRINT, etc.
 * to detect emulators.  Generic emulators return "generic", "sdk", or
 * "unknown" which immediately reveal the lab environment.
 *
 * This script intercepts all read access to android.os.Build static fields
 * and substitutes values from the PHANTOM device persona.
 *
 * Injection: Frida.inject_script() at process attach, before any APK code runs.
 * Template: Replace PERSONA_* placeholders at runtime from Python controller.
 *
 * Tested against: ToxicPanda Build-check, SpyNote emulator detection,
 *                 Cerberus anti-VM (Build.HARDWARE check).
 */

(function () {
    "use strict";

    // ── Persona values injected by Python at runtime ──────────────────────
    var PERSONA = {
        MANUFACTURER:    "PERSONA_MANUFACTURER",
        MODEL:           "PERSONA_MODEL",
        BRAND:           "PERSONA_BRAND",
        DEVICE:          "PERSONA_DEVICE",
        PRODUCT:         "PERSONA_PRODUCT",
        BOARD:           "PERSONA_DEVICE",       // Same as DEVICE for target phones
        HARDWARE:        "qcom",                  // Qualcomm — most common in India
        DISPLAY:         "PERSONA_BUILD_ID",
        ID:              "PERSONA_BUILD_ID",
        FINGERPRINT:     "PERSONA_FINGERPRINT",
        HOST:            "buildhost",
        TYPE:            "user",
        TAGS:            "release-keys",
        USER:            "droidbuilder",
        SERIAL:          "unknown",
        BOOTLOADER:      "unknown",
        RADIO:           "unknown",
    };

    var SDK_INT = parseInt("PERSONA_SDK_INT", 10);
    var ANDROID_VERSION = "PERSONA_ANDROID_VERSION";

    // ── Hook android.os.Build ─────────────────────────────────────────────
    try {
        var Build = Java.use("android.os.Build");

        // Intercept static field reads via reflection
        var overrideField = function(fieldName, value) {
            try {
                var field = Build.class.getDeclaredField(fieldName);
                field.setAccessible(true);
                field.set(null, value);
            } catch (e) {
                // Field may not exist on all Android versions — silently ignore
            }
        };

        Java.perform(function () {
            overrideField("MANUFACTURER", PERSONA.MANUFACTURER);
            overrideField("MODEL",        PERSONA.MODEL);
            overrideField("BRAND",        PERSONA.BRAND);
            overrideField("DEVICE",       PERSONA.DEVICE);
            overrideField("PRODUCT",      PERSONA.PRODUCT);
            overrideField("BOARD",        PERSONA.BOARD);
            overrideField("HARDWARE",     PERSONA.HARDWARE);
            overrideField("DISPLAY",      PERSONA.DISPLAY);
            overrideField("ID",           PERSONA.ID);
            overrideField("FINGERPRINT",  PERSONA.FINGERPRINT);
            overrideField("HOST",         PERSONA.HOST);
            overrideField("TYPE",         PERSONA.TYPE);
            overrideField("TAGS",         PERSONA.TAGS);
            overrideField("USER",         PERSONA.USER);
            overrideField("SERIAL",       PERSONA.SERIAL);

            console.log("[PHANTOM/ManufacturerHook] Build fields overridden: "
                + PERSONA.MANUFACTURER + "/" + PERSONA.MODEL);
        });
    } catch (e) {
        console.error("[PHANTOM/ManufacturerHook] Build hook failed: " + e.message);
    }

    // ── Hook Build.VERSION ────────────────────────────────────────────────
    try {
        Java.perform(function () {
            var BuildVersion = Java.use("android.os.Build$VERSION");

            var sdkField = BuildVersion.class.getDeclaredField("SDK_INT");
            sdkField.setAccessible(true);
            sdkField.setInt(null, SDK_INT);

            var releaseField = BuildVersion.class.getDeclaredField("RELEASE");
            releaseField.setAccessible(true);
            releaseField.set(null, ANDROID_VERSION);

            console.log("[PHANTOM/ManufacturerHook] VERSION.SDK_INT=" + SDK_INT
                + " VERSION.RELEASE=" + ANDROID_VERSION);
        });
    } catch (e) {
        console.error("[PHANTOM/ManufacturerHook] VERSION hook failed: " + e.message);
    }

    // ── Hook SystemProperties.get() ───────────────────────────────────────
    // Some malware reads build properties directly via SystemProperties.
    try {
        Java.perform(function () {
            var SystemProperties = Java.use("android.os.SystemProperties");
            SystemProperties.get.overload("java.lang.String").implementation = function (key) {
                switch (key) {
                    case "ro.product.manufacturer": return PERSONA.MANUFACTURER;
                    case "ro.product.model":        return PERSONA.MODEL;
                    case "ro.product.brand":        return PERSONA.BRAND;
                    case "ro.product.device":       return PERSONA.DEVICE;
                    case "ro.build.version.sdk":    return String(SDK_INT);
                    case "ro.build.version.release":return ANDROID_VERSION;
                    case "ro.build.fingerprint":    return PERSONA.FINGERPRINT;
                    default: return this.get(key);
                }
            };
            console.log("[PHANTOM/ManufacturerHook] SystemProperties.get() hooked");
        });
    } catch (e) {
        console.error("[PHANTOM/ManufacturerHook] SystemProperties hook failed: " + e.message);
    }

})();
