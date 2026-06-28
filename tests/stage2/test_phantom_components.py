import math
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent.parent))
class TestSensoryEmulator(unittest.TestCase):
    def setUp(self):
        from phantom.sensory_emulation import SensoryEmulator
        self.emulator=SensoryEmulator(seed=42)
    def test_generates_correct_sample_count(self):
        samples=list(self.emulator.generate_stream(100))
        self.assertEqual(len(samples),100)
    def test_gyroscope_within_physical_range(self):
        samples=list(self.emulator.generate_stream(300))
        for s in samples:
            self.assertGreater(s.gyro_x,-5.0,"gyro_x too low")
            self.assertLess(s.gyro_x,5.0,"gyro_x too high")
            self.assertGreater(s.gyro_y,-5.0)
            self.assertLess(s.gyro_y,5.0)
    def test_gyroscope_has_nonzero_variance(self):
        samples=list(self.emulator.generate_stream(200))
        gyro_x_vals=[s.gyro_x for s in samples]
        mean=sum(gyro_x_vals)/len(gyro_x_vals)
        variance=sum((v-mean)**2 for v in gyro_x_vals)/len(gyro_x_vals)
        self.assertGreater(variance,1e-6,"Gyroscope variance is zero — emulator detected")
    def test_accelerometer_near_gravity(self):
        samples=list(self.emulator.generate_stream(200))
        z_vals=[s.accel_z for s in samples]
        mean_z=sum(z_vals)/len(z_vals)
        self.assertGreater(mean_z,8.0,"Accel Z too low — not plausible")
        self.assertLess(mean_z,12.0,"Accel Z too high — not plausible")
    def test_light_sensor_nonnegative(self):
        samples=list(self.emulator.generate_stream(300))
        for s in samples:
            self.assertGreaterEqual(s.light,0.0,"Negative lux value detected")
    def test_proximity_is_far(self):
        samples=list(self.emulator.generate_stream(10))
        for s in samples:
            self.assertAlmostEqual(s.proximity,5.0)
    def test_android_json_schema_complete(self):
        sample=self.emulator.next_sample()
        sensor_json=self.emulator.sample_as_android_json(sample)
        required_keys=[
            "TYPE_GYROSCOPE","TYPE_ACCELEROMETER",
            "TYPE_LIGHT","TYPE_PROXIMITY",
        ]
        for key in required_keys:
            self.assertIn(key,sensor_json,f"Missing sensor key:{key}")
        for key in required_keys:
            self.assertIn("timestamp",sensor_json[key])
            self.assertIn("values",sensor_json[key])
            self.assertIsInstance(sensor_json[key]["values"],list)
    def test_variance_report_structure(self):
        report=self.emulator.compute_variance_report(n_samples=100)
        for sensor_key in("gyro_x","gyro_y","gyro_z","accel_x","accel_y","accel_z","light"):
            self.assertIn(sensor_key,report)
            self.assertIn("mean",report[sensor_key])
            self.assertIn("variance",report[sensor_key])
            self.assertIn("std",report[sensor_key])
    def test_reset_restores_equilibrium(self):
        _=list(self.emulator.generate_stream(50))
        self.emulator.reset()
        sample=self.emulator.next_sample()
        import time
        t_now_ns=time.time_ns()
        self.assertLess(abs(sample.timestamp_ns-t_now_ns),1_000_000_000)
class TestDevicePersonaGenerator(unittest.TestCase):
    def setUp(self):
        from phantom.device_persona import DevicePersonaGenerator
        self.gen=DevicePersonaGenerator(seed=99)
    def _luhn_valid(self,number:str)->bool:
        digits=[int(d)for d in number]
        for i in range(len(digits)-2,-1,-2):
            digits[i]*=2
            if digits[i]>9:
                digits[i]-=9
        return sum(digits)%10==0
    def test_persona_imei_is_15_digits(self):
        persona=self.gen.generate()
        self.assertEqual(len(persona.imei),15)
        self.assertTrue(persona.imei.isdigit())
    def test_imei_luhn_valid(self):
        for _ in range(10):
            persona=self.gen.generate()
            self.assertTrue(
                self._luhn_valid(persona.imei),
                f"IMEI Luhn check failed:{persona.imei}"
            )
    def test_iccid_is_20_digits(self):
        persona=self.gen.generate()
        self.assertEqual(len(persona.iccid),20)
        self.assertTrue(persona.iccid.isdigit())
    def test_iccid_luhn_valid(self):
        for _ in range(5):
            persona=self.gen.generate()
            self.assertTrue(
                self._luhn_valid(persona.iccid),
                f"ICCID Luhn check failed:{persona.iccid}"
            )
    def test_imsi_is_15_digits(self):
        persona=self.gen.generate()
        self.assertEqual(len(persona.imsi),15)
        self.assertTrue(persona.imsi.isdigit())
    def test_phone_starts_with_plus91(self):
        persona=self.gen.generate()
        self.assertTrue(
            persona.phone_number.startswith("+91"),
            f"Phone does not start with+91:{persona.phone_number}"
        )
    def test_country_iso_is_in(self):
        persona=self.gen.generate()
        self.assertEqual(persona.country_iso,"in")
    def test_session_id_is_16_hex_chars(self):
        persona=self.gen.generate()
        self.assertEqual(len(persona.session_id),16)
        int(persona.session_id,16)
    def test_to_frida_context_keys_present(self):
        from phantom.device_persona import DevicePersonaGenerator
        gen=DevicePersonaGenerator(seed=7)
        persona=gen.generate()
        ctx=gen.to_frida_context(persona)
        required_keys=[
            "manufacturer","model","brand","device","product",
            "android_version","sdk_int","build_id","fingerprint",
            "country_iso","imei","imsi","phone_number",
        ]
        for key in required_keys:
            self.assertIn(key,ctx,f"Missing frida_context key:{key}")
    def test_to_llm_context_is_nonempty_string(self):
        from phantom.device_persona import DevicePersonaGenerator
        gen=DevicePersonaGenerator(seed=3)
        persona=gen.generate()
        ctx=gen.to_llm_context(persona)
        self.assertIsInstance(ctx,str)
        self.assertGreater(len(ctx),50)
        self.assertIn("DEVICE ENVIRONMENT",ctx)
    def test_persona_index_selects_specific_device(self):
        from phantom.device_persona import DevicePersonaGenerator,PHANTOM_DEVICE_PERSONAS
        gen=DevicePersonaGenerator(seed=1)
        persona=gen.generate(persona_index=0)
        expected_model=PHANTOM_DEVICE_PERSONAS[0]["model"]
        self.assertEqual(persona.model,expected_model)
    def test_two_sessions_have_different_imei(self):
        p1=self.gen.generate()
        p2=self.gen.generate()
        self.assertNotEqual(p1.imei,p2.imei)
class TestBehavioralBiometricGenerator(unittest.TestCase):
    def setUp(self):
        from phantom.behavioral_biometrics import BehavioralBiometricGenerator
        self.gen=BehavioralBiometricGenerator(seed=42)
    def test_typing_session_has_correct_key_count(self):
        text="TestPassword123"
        session=self.gen.simulate_typing(text)
        self.assertEqual(len(session.key_events),len(text))
    def test_iki_values_in_valid_range(self):
        session=self.gen.simulate_typing("Hello World")
        for event in session.key_events[1:]:
            self.assertGreaterEqual(event.iki_ms,30.0,f"IKI too short:{event.iki_ms}")
            self.assertLessEqual(event.iki_ms,2000.0,f"IKI too long:{event.iki_ms}")
    def test_total_duration_positive(self):
        session=self.gen.simulate_typing("password")
        self.assertGreater(session.total_duration_ms,0.0)
    def test_press_duration_positive(self):
        session=self.gen.simulate_typing("abc")
        for event in session.key_events:
            self.assertGreater(event.press_duration_ms,0.0)
    def test_tap_returns_two_events(self):
        events=self.gen.simulate_tap(x=540.0,y=960.0)
        self.assertEqual(len(events),2)
        self.assertEqual(events[0].action,"DOWN")
        self.assertEqual(events[1].action,"UP")
    def test_tap_coordinates_close_to_target(self):
        x_target,y_target=540.0,960.0
        events=self.gen.simulate_tap(x=x_target,y=y_target,target_radius=20.0)
        for event in events:
            self.assertAlmostEqual(event.x,x_target,delta=60.0)
            self.assertAlmostEqual(event.y,y_target,delta=60.0)
    def test_swipe_starts_with_down_ends_with_up(self):
        events=self.gen.simulate_swipe(100.0,500.0,900.0,500.0)
        self.assertGreater(len(events),2)
        self.assertEqual(events[0].action,"DOWN")
        self.assertEqual(events[-1].action,"UP")
    def test_field_navigation_delay_in_range(self):
        for _ in range(20):
            delay=self.gen.field_navigation_delay_ms()
            self.assertGreaterEqual(delay,400.0)
            self.assertLessEqual(delay,1200.0)
    def test_cognitive_load_increases_timing(self):
        sess_low=self.gen.simulate_typing("hello",cognitive_load=0.0)
        sess_high=self.gen.simulate_typing("hello",cognitive_load=1.0)
        self.assertGreater(sess_high.mean_iki_ms,sess_low.mean_iki_ms)
if __name__=="__main__":
    unittest.main(verbosity=2)
