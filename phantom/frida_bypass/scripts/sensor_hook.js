/**
 * ORACLE-TMF · phantom/frida_bypass/scripts/sensor_hook.js
 * ===========================================================
 * Frida hook: Spoof SensorManager to return OU-generated sensor values.
 *
 * ToxicPanda specifically checks:
 *   • SensorManager.registerListener() for TYPE_GYROSCOPE
 *   • Validates that gyroscope variance > 0 (real device > 0, emulator = 0)
 *
 * Chameleon checks:
 *   • Light sensor value must be in a valid range (20–10000 lux)
 *
 * This hook intercepts SensorEvent delivery and substitutes OU-generated
 * values from the PHANTOM sensory emulation module.
 *
 * Values are injected as JSON via template placeholders:
 *   SENSOR_GYRO_X, SENSOR_GYRO_Y, SENSOR_GYRO_Z  (rad/s)
 *   SENSOR_ACCEL_X, SENSOR_ACCEL_Y, SENSOR_ACCEL_Z (m/s²)
 *   SENSOR_LIGHT  (lux)
 *   SENSOR_PROX   (cm)
 *
 * These are updated by the Python controller with new OU samples
 * at the configured sensor refresh rate (60 Hz).
 */

(function () {
    "use strict";

    // ── Injected OU sensor values (refreshed by Python controller) ────────
    var SENSOR_STATE = {
        gyro:  { x: parseFloat("SENSOR_GYRO_X"),  y: parseFloat("SENSOR_GYRO_Y"),  z: parseFloat("SENSOR_GYRO_Z") },
        accel: { x: parseFloat("SENSOR_ACCEL_X"), y: parseFloat("SENSOR_ACCEL_Y"), z: parseFloat("SENSOR_ACCEL_Z") },
        light:  parseFloat("SENSOR_LIGHT"),
        prox:   parseFloat("SENSOR_PROX"),
    };

    // Add small random perturbation to prevent detection of static values
    function jitter(value, scale) {
        return value + (Math.random() * 2 - 1) * scale;
    }

    // ── SensorEventListener.onSensorChanged() hook ────────────────────────
    try {
        Java.perform(function () {
            var Sensor = Java.use("android.hardware.Sensor");
            var SensorEvent = Java.use("android.hardware.SensorEvent");

            // Hook the SensorEvent.values field access
            // We intercept via the registered listener's onSensorChanged callback
            var SensorManager = Java.use("android.hardware.SensorManager");

            SensorManager.registerListener.overload(
                "android.hardware.SensorEventListener",
                "android.hardware.Sensor",
                "int"
            ).implementation = function (listener, sensor, delay) {
                var sensorType = sensor.getType();

                // Wrap the listener to intercept delivered SensorEvents
                var WrappedListener = Java.registerClass({
                    name: "com.oracle.phantom.WrappedSensorListener_" + sensorType,
                    implements: [Java.use("android.hardware.SensorEventListener")],
                    fields: {
                        delegate: "android.hardware.SensorEventListener",
                    },
                    methods: {
                        onSensorChanged: function (event) {
                            var TYPE_GYROSCOPE   = 4;
                            var TYPE_ACCELEROMETER = 1;
                            var TYPE_LIGHT       = 5;
                            var TYPE_PROXIMITY   = 8;

                            var type = event.sensor.value.getType();

                            if (type === TYPE_GYROSCOPE) {
                                event.values.value[0] = jitter(SENSOR_STATE.gyro.x, 0.002);
                                event.values.value[1] = jitter(SENSOR_STATE.gyro.y, 0.002);
                                event.values.value[2] = jitter(SENSOR_STATE.gyro.z, 0.001);
                            } else if (type === TYPE_ACCELEROMETER) {
                                event.values.value[0] = jitter(SENSOR_STATE.accel.x, 0.05);
                                event.values.value[1] = jitter(SENSOR_STATE.accel.y, 0.05);
                                event.values.value[2] = jitter(SENSOR_STATE.accel.z, 0.02);
                            } else if (type === TYPE_LIGHT) {
                                event.values.value[0] = jitter(SENSOR_STATE.light, 5.0);
                            } else if (type === TYPE_PROXIMITY) {
                                event.values.value[0] = SENSOR_STATE.prox;
                            }

                            // Deliver modified event to real listener
                            this.delegate.value.onSensorChanged(event);
                        },
                        onAccuracyChanged: function (sensor, accuracy) {
                            this.delegate.value.onAccuracyChanged(sensor, accuracy);
                        },
                    },
                });

                var wrapped = WrappedListener.$new();
                wrapped.delegate.value = listener;
                return this.registerListener(wrapped, sensor, delay);
            };

            console.log("[PHANTOM/SensorHook] SensorManager.registerListener() hooked");
        });
    } catch (e) {
        console.error("[PHANTOM/SensorHook] SensorManager hook failed: " + e.message);
    }

    // ── Expose update function for Python controller ───────────────────────
    // Python calls phantom_update_sensors(json) via Frida RPC to refresh values
    rpc.exports = {
        updateSensors: function (sensorJson) {
            try {
                var state = JSON.parse(sensorJson);
                if (state.gyro) {
                    SENSOR_STATE.gyro.x = state.gyro.x;
                    SENSOR_STATE.gyro.y = state.gyro.y;
                    SENSOR_STATE.gyro.z = state.gyro.z;
                }
                if (state.accel) {
                    SENSOR_STATE.accel.x = state.accel.x;
                    SENSOR_STATE.accel.y = state.accel.y;
                    SENSOR_STATE.accel.z = state.accel.z;
                }
                if (typeof state.light !== "undefined") {
                    SENSOR_STATE.light = state.light;
                }
                return true;
            } catch (e) {
                return false;
            }
        },
        getSensorState: function () {
            return JSON.stringify(SENSOR_STATE);
        },
    };

    console.log("[PHANTOM/SensorHook] Sensor spoofing active");
})();
