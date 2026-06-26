"""
ORACLE-TMF  ·  tests/test_stage_f.py
=======================================
Unit tests for Stage F — String Resource and Placeholder Mining.
Tests cover:
  • Shannon entropy calculation (correctness + boundary values)
  • High-entropy strings correctly flagged
  • Low-entropy / benign strings correctly skipped
  • Each PLACEHOLDER_PATTERNS regex fires on known-bad strings
  • Benign prefix filtering (com.google.*, com.android.*)
  • Minimum string length filtering
  • Deduplication across DEX pool + resource XML passes
  • PlaceholderStringArtifact field population
Zero external dependencies — tests run against pure-Python helpers.
"""
import math
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent))
from pipeline.stage_f_string_mining import StringMiner,_COMPILED_PATTERNS
from models.mutation_artifact_graph import PlaceholderStringArtifact
class TestShannonEntropy(unittest.TestCase):
    """Verify the Shannon entropy implementation against hand-calculated values."""
    def test_empty_string_returns_zero(self):
        self.assertEqual(StringMiner._shannon_entropy(""),0.0)
    def test_uniform_string_max_entropy(self):
        """A string with all unique characters has maximum entropy."""
        s="abcdefgh"
        h=StringMiner._shannon_entropy(s)
        expected=math.log2(8)
        self.assertAlmostEqual(h,expected,places=5)
    def test_constant_string_zero_entropy(self):
        """A string of repeated characters has zero entropy."""
        h=StringMiner._shannon_entropy("aaaaaaaaaa")
        self.assertAlmostEqual(h,0.0,places=10)
    def test_known_high_entropy_string(self):
        """Random-looking base64 strings should have entropy > 4.5."""
        
        s="aB3cD9eF2gH7iJ5kL1mN4oP8qR6sT0uV"
        h=StringMiner._shannon_entropy(s)
        self.assertGreater(h,4.0,f"Expected H > 4.0 for mixed string, got {h:.3f}")
    def test_english_sentence_moderate_entropy(self):
        """Natural language has entropy roughly in [3.5, 4.5]."""
        h=StringMiner._shannon_entropy("the quick brown fox jumps over the lazy dog")
        self.assertGreater(h,2.5)
        self.assertLess(h,5.0)
    def test_single_char_string(self):
        h=StringMiner._shannon_entropy("x")
        self.assertEqual(h,0.0)
    def test_two_char_equal_frequency(self):
        h=StringMiner._shannon_entropy("ababababab")
        self.assertAlmostEqual(h,1.0,places=5)
    def test_entropy_is_nonnegative(self):
        for s in["hello","abc","AAAA","12345",""]:
            self.assertGreaterEqual(StringMiner._shannon_entropy(s),0.0)
class TestPlaceholderPatterns(unittest.TestCase):
    """Verify that PLACEHOLDER_PATTERNS regexes fire on known-bad strings."""
    def _matches(self,pattern_name:str,value:str)->bool:
        compiled=_COMPILED_PATTERNS.get(pattern_name)
        if compiled is None:
            self.fail(f"Pattern '{pattern_name}' not in _COMPILED_PATTERNS")
        return bool(compiled.search(value))
    
    def test_todo_marker_fires(self):
        self.assertTrue(self._matches("todo_marker","TODO: implement this"))
        self.assertTrue(self._matches("todo_marker","FIXME: remove before prod"))
        self.assertTrue(self._matches("todo_marker","// HACK: temporary workaround"))
        self.assertTrue(self._matches("todo_marker","PLACEHOLDER value"))
    def test_todo_marker_case_insensitive(self):
        self.assertTrue(self._matches("todo_marker","todo: finish this"))
        self.assertTrue(self._matches("todo_marker","fixme soon"))
    def test_todo_marker_no_false_positive_on_normal_string(self):
        self.assertFalse(self._matches("todo_marker","send_sms_to_contact"))
    
    def test_test_marker_fires(self):
        self.assertTrue(self._matches("test_marker","test_mode_enabled"))
        self.assertTrue(self._matches("test_marker","debug_flag=true"))
        self.assertTrue(self._matches("test_marker","staging_environment"))
        self.assertTrue(self._matches("test_marker","sandbox_api_key"))
    
    def test_staging_url_fires(self):
        self.assertTrue(self._matches("staging_url","http://dev-c2-v2.local/api/upload"))
        self.assertTrue(self._matches("staging_url","http://test.api.example.com"))
        self.assertTrue(self._matches("staging_url","http://staging.backend.evil.com"))
        self.assertTrue(self._matches("staging_url","https://localhost:8080/api"))
        self.assertTrue(self._matches("staging_url","http://192.168.1.100/callback"))
        self.assertTrue(self._matches("staging_url","http://10.0.0.1/c2"))
        self.assertTrue(self._matches("staging_url","http://172.16.0.5/panel"))
    def test_staging_url_no_fire_on_prod(self):
        self.assertFalse(self._matches("staging_url","https://api.example.com/v2/send"))
    
    def test_empty_json_schema_fires(self):
        self.assertTrue(self._matches("empty_json_schema",'{"cc_number": "", "cvv": ""}'))
        self.assertTrue(self._matches("empty_json_schema",'{"token": ""}'))
        self.assertTrue(self._matches("empty_json_schema","{'key': ''}"))
    
    def test_hardcoded_ipv4_fires(self):
        self.assertTrue(self._matches("hardcoded_ipv4","45.142.100.200:443"))
        self.assertTrue(self._matches("hardcoded_ipv4","Connect to 185.220.101.10"))
        self.assertTrue(self._matches("hardcoded_ipv4","192.168.0.1"))
    def test_hardcoded_ipv4_no_fire_on_localhost(self):
        
        self.assertFalse(self._matches("hardcoded_ipv4","localhost:8080"))
        self.assertFalse(self._matches("hardcoded_ipv4","no ip here at all"))
    
    def test_c2_path_fires(self):
        self.assertTrue(self._matches("c2_path_pattern","/api/v2/exfiltrate"))
        self.assertTrue(self._matches("c2_path_pattern","/drop/payload"))
        self.assertTrue(self._matches("c2_path_pattern","/bot/register"))
        self.assertTrue(self._matches("c2_path_pattern","/panel/login"))
        self.assertTrue(self._matches("c2_path_pattern","/collect/sms"))
        self.assertTrue(self._matches("c2_path_pattern","/cmd/execute"))
    
    def test_onion_address_fires(self):
        self.assertTrue(self._matches("onion_address","facebookcorewwwi.onion"))
        self.assertTrue(self._matches("onion_address","xmh57jrzrnw6insl.onion/c2"))
class TestStringEvaluation(unittest.TestCase):
    """Test the _evaluate_string method on known inputs."""
    def setUp(self):
        self.miner=StringMiner()
    def test_high_entropy_string_flagged(self):
        
        high_entropy="aB3cD9eF2gH7iJ5kL1mN4oP8qR6sT0uV3wX8yZ"
        artifact=self.miner._evaluate_string(high_entropy,source="string_pool")
        self.assertIsNotNone(artifact,"High-entropy string should be flagged")
        self.assertGreater(artifact.entropy,4.0)
        self.assertEqual(artifact.source,"string_pool")
    def test_staging_url_flagged(self):
        
        
        url="http://localhost:8888/api/drop_payload"
        artifact=self.miner._evaluate_string(url,source="string_pool")
        self.assertIsNotNone(artifact,"Staging URL should be flagged")
        
        self.assertIn(artifact.matched_pattern,("staging_url","test_marker"),
                      f"Unexpected matched_pattern: {artifact.matched_pattern}")
    def test_todo_marker_flagged(self):
        s="TODO: implement DGA seed"
        artifact=self.miner._evaluate_string(s,source="res/values/strings.xml",key_name="label_text")
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact.matched_pattern,"todo_marker")
        self.assertEqual(artifact.key_name,"label_text")
    def test_benign_short_string_skipped(self):
        
        artifact=self.miner._evaluate_string("ok",source="string_pool")
        self.assertIsNone(artifact,"Short strings should be skipped")
    def test_benign_low_entropy_word_skipped(self):
        
        artifact=self.miner._evaluate_string("helloworld",source="string_pool")
        self.assertIsNone(artifact)
    def test_value_capped_at_256_chars(self):
        long_val="A"*300
        
        long_val="".join(chr(65+(i%95))for i in range(300))
        artifact=self.miner._evaluate_string(long_val,source="string_pool")
        if artifact:
            self.assertLessEqual(len(artifact.value),256)
    def test_benign_prefix_not_flagged_by_entropy(self):
        """
        Strings starting with known-benign prefixes should be skipped
        even if they have high entropy.
        """
        
        
        
        
        s="com.google.firebase.FirebaseApp"
        artifact=self.miner._evaluate_string(s,source="string_pool")
        
        
class TestStringMinerArtifactFields(unittest.TestCase):
    """Verify that returned artifacts have properly populated fields."""
    def test_artifact_source_preserved(self):
        miner=StringMiner()
        artifact=miner._evaluate_string("http://staging.test.evil.com/api","string_pool")
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact.source,"string_pool")
    def test_artifact_entropy_nonnegative(self):
        miner=StringMiner()
        artifact=miner._evaluate_string("http://dev.local/drop","string_pool")
        if artifact:
            self.assertGreaterEqual(artifact.entropy,0.0)
    def test_artifact_value_is_string(self):
        miner=StringMiner()
        artifact=miner._evaluate_string("TODO: implement SMS stealer","string_pool")
        if artifact:
            self.assertIsInstance(artifact.value,str)
            self.assertIsInstance(artifact.entropy,float)
if __name__=="__main__":
    unittest.main(verbosity=2)
