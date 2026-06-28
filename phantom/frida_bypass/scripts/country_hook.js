/**
 * ORACLE-TMF · phantom/frida_bypass/scripts/country_hook.js
 * ===========================================================
 * Frida hook: Spoof TelephonyManager to return target country/operator values.
 *
 * Banking trojans are geofenced: they check SIM country ISO, network
 * operator, and sometimes cell tower country code before activating.
 * A lab SIM (or emulator with generic config) will cause the malware
 * to detect the wrong jurisdiction and refuse to activate.
 *
 * This hook intercepts:
 *   TelephonyManager.getSimCountryIso()   → target country ISO
 *   TelephonyManager.getNetworkCountryIso() → target country ISO
 *   TelephonyManager.getSimOperator()     → MCC+MNC for target operator
 *   TelephonyManager.getSimOperatorName() → Operator display name
 *   TelephonyManager.getNetworkOperator() → Network MCC+MNC
 *   TelephonyManager.getNetworkOperatorName()
 *   TelephonyManager.getLine1Number()     → Honeytoken phone number
 *   TelephonyManager.getDeviceId()        → Honeytoken IMEI
 *   TelephonyManager.getImei()            → Honeytoken IMEI
 *   TelephonyManager.getSubscriberId()    → Honeytoken IMSI
 *
 * Template placeholders replaced by Python at runtime.
 */

(function () {
    "use strict";

    // ── Persona values (injected from Python) ─────────────────────────────
    var COUNTRY_ISO          = "PERSONA_COUNTRY_ISO";
    var NETWORK_OPERATOR     = "PERSONA_NETWORK_OPERATOR";
    var NETWORK_OPERATOR_NAME= "PERSONA_NETWORK_OPERATOR_NAME";
    var SIM_OPERATOR         = "PERSONA_SIM_OPERATOR";
    var SIM_OPERATOR_NAME    = "PERSONA_SIM_OPERATOR_NAME";
    var IMEI                 = "PERSONA_IMEI";
    var IMSI                 = "PERSONA_IMSI";
    var PHONE_NUMBER         = "PERSONA_PHONE_NUMBER";

    // ── TelephonyManager hook ─────────────────────────────────────────────
    try {
        Java.perform(function () {
            var TelephonyManager = Java.use("android.telephony.TelephonyManager");

            TelephonyManager.getSimCountryIso.implementation = function () {
                return COUNTRY_ISO;
            };
            TelephonyManager.getNetworkCountryIso.implementation = function () {
                return COUNTRY_ISO;
            };
            TelephonyManager.getSimOperator.implementation = function () {
                return SIM_OPERATOR;
            };
            TelephonyManager.getSimOperatorName.implementation = function () {
                return SIM_OPERATOR_NAME;
            };
            TelephonyManager.getNetworkOperator.implementation = function () {
                return NETWORK_OPERATOR;
            };
            TelephonyManager.getNetworkOperatorName.implementation = function () {
                return NETWORK_OPERATOR_NAME;
            };
            TelephonyManager.getLine1Number.implementation = function () {
                return PHONE_NUMBER;
            };

            // getDeviceId() — deprecated in API 26 but still called by older trojans
            try {
                TelephonyManager.getDeviceId.overload().implementation = function () {
                    return IMEI;
                };
                TelephonyManager.getDeviceId.overload("int").implementation = function (slotIndex) {
                    return IMEI;
                };
            } catch (e) { /* API-level variation — ignore */ }

            // getImei() — API 26+ replacement
            try {
                TelephonyManager.getImei.overload().implementation = function () {
                    return IMEI;
                };
                TelephonyManager.getImei.overload("int").implementation = function (slotIndex) {
                    return IMEI;
                };
            } catch (e) { /* API-level variation — ignore */ }

            // getSubscriberId() → IMSI
            TelephonyManager.getSubscriberId.implementation = function () {
                return IMSI;
            };

            console.log("[PHANTOM/CountryHook] TelephonyManager hooked → "
                + COUNTRY_ISO + " / " + SIM_OPERATOR_NAME
                + " IMEI=" + IMEI);
        });
    } catch (e) {
        console.error("[PHANTOM/CountryHook] TelephonyManager hook failed: " + e.message);
    }

    // ── Locale / timezone ─────────────────────────────────────────────────
    // Some malware checks Locale.getDefault() for country-based activation.
    try {
        Java.perform(function () {
            var Locale = Java.use("java.util.Locale");

            Locale.getDefault.implementation = function () {
                return Locale.forLanguageTag("en-" + COUNTRY_ISO.toUpperCase());
            };

            console.log("[PHANTOM/CountryHook] Locale.getDefault() → en-"
                + COUNTRY_ISO.toUpperCase());
        });
    } catch (e) {
        console.error("[PHANTOM/CountryHook] Locale hook failed: " + e.message);
    }

    // ── ConnectivityManager — hide VPN / proxy usage ──────────────────────
    try {
        Java.perform(function () {
            var ConnectivityManager = Java.use("android.net.ConnectivityManager");
            // Hide the active network type override that reveals the proxy
            var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");

            console.log("[PHANTOM/CountryHook] ConnectivityManager hook registered");
        });
    } catch (e) {
        console.error("[PHANTOM/CountryHook] ConnectivityManager hook failed: " + e.message);
    }

})();
