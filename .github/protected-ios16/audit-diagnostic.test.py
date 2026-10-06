"""Synthetic exception projection. No actual IPA, provider, key or runtime input."""
import importlib.util, json, unittest
from pathlib import Path
root=Path(__file__).parent
spec=importlib.util.spec_from_file_location('native_diagnostic',root/'native-audit.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
legacy_spec=importlib.util.spec_from_file_location('legacy_native_tests',root/'native-byte.test.py')
legacy=importlib.util.module_from_spec(legacy_spec);legacy_spec.loader.exec_module(legacy)
class Projection(unittest.TestCase):
    def failure(self,source,file='native-audit.py'):
        try:exec(compile(source,str(root/file),'exec'),{})
        except Exception as error:return module.failure_projection(error)
        self.fail('missing synthetic exception')
    def test_original_accepting_prefix_and_seven_original_controls(self):
        original=(root.parent/'ios16-protected-github-macos-context-v2-20261006/native-audit.py').read_bytes()
        current=(root/'native-audit.py').read_bytes()
        self.assertEqual(original.split(b"if __name__=='__main__':")[0],current.split(b'def failure_projection(error):')[0])
        self.assertEqual(unittest.defaultTestLoader.loadTestsFromModule(legacy).countTestCases(),7)
    def test_exact_closed_failure_and_useful_two_frame_location(self):
        value=self.failure("def require(value):\n if not value: raise ValueError('PRIVATE code/customer/key/archive material')\ndef audit():\n require(False)\naudit()\n")
        self.assertEqual(set(value),{'nativeAuditVerified','diagnosticOnly','exceptionType','sourceFrames'})
        self.assertEqual(value,{'nativeAuditVerified':False,'diagnosticOnly':True,'exceptionType':'ValueError','sourceFrames':[{'file':'native-audit.py','line':4},{'file':'native-audit.py','line':2}]})
        self.assertNotIn('PRIVATE',json.dumps(value))
    def test_each_class_is_finite_and_never_stringifies_message(self):
        classes=((ValueError,'ValueError'),(AssertionError,'AssertionError'),(KeyError,'KeyError'),(TypeError,'TypeError'),(AttributeError,'AttributeError'),(IndexError,'IndexError'),(OverflowError,'OverflowError'),(FileNotFoundError,'FileNotFoundError'),(PermissionError,'PermissionError'),(OSError,'OSError'),(UnicodeDecodeError,'UnicodeDecodeError'),(json.JSONDecodeError,'JSONDecodeError'),(module.zipfile.BadZipFile,'BadZipFile'),(module.plistlib.InvalidFileException,'InvalidFileException'),(module.struct.error,'StructError'))
        for kind,label in classes:
            if kind is UnicodeDecodeError:error=kind('utf8',b'PRIVATE',0,1,'PRIVATE')
            elif kind is json.JSONDecodeError:error=kind('PRIVATE','PRIVATE',0)
            else:error=kind('PRIVATE')
            result=module.failure_projection(error)
            self.assertEqual(result['exceptionType'],label);self.assertEqual(result['sourceFrames'],[])
            self.assertNotIn('PRIVATE',json.dumps(result))
    def test_custom_class_name_and_str_are_never_exposed_or_called(self):
        class PrivateValueError(ValueError):
            def __str__(self):raise AssertionError('must not stringify')
        value=module.failure_projection(PrivateValueError('PRIVATE'))
        self.assertEqual(value['exceptionType'],'OtherSuppressed');self.assertNotIn('Private',json.dumps(value))
    def test_reviewed_imported_guard_name_and_function_only(self):
        value=self.failure("def verify_resource_hashes():\n raise KeyError('PRIVATE member name')\nverify_resource_hashes()\n",'artifact_guard.py')
        self.assertEqual(value['sourceFrames'],[{'file':'artifact_guard.py','line':2}])
        unknown=self.failure("def secret_method():\n raise ValueError('PRIVATE')\nsecret_method()\n",'artifact_guard.py')
        self.assertEqual(unknown['sourceFrames'],[])
    def test_foreign_same_basename_and_unknown_filename_are_suppressed(self):
        for name in ['../../secret/native-audit.py','unknown.py','PRIVATE/customer-code.py']:
            value=self.failure("def audit():\n raise ValueError('PRIVATE')\naudit()\n",name)
            self.assertEqual(value['sourceFrames'],[]);self.assertNotIn('PRIVATE',json.dumps(value))
    def test_deep_frame_projection_caps_at_two(self):
        value=self.failure("def require():\n raise ValueError('PRIVATE')\ndef executable():\n require()\ndef audit():\n executable()\naudit()\n")
        self.assertEqual(value['sourceFrames'],[{'file':'native-audit.py','line':4},{'file':'native-audit.py','line':2}])
    def test_out_of_bound_line_suppressed(self):
        value=self.failure('\n'*10001+"def audit():\n raise ValueError('PRIVATE')\naudit()\n")
        self.assertEqual(value['sourceFrames'],[])
    def test_helper_does_not_read_source_or_archive(self):
        original=module.Path
        class PathNoReads:
            def __init__(self,value):self.value=value
            def with_name(self,name):return str(root/name)
            def read_bytes(self):raise AssertionError('private read')
        try:
            module.Path=PathNoReads
            value=module.failure_projection(ValueError('PRIVATE'))
            self.assertEqual(value['sourceFrames'],[])
        finally:module.Path=original
def load_tests(loader,tests,pattern):
    tests.addTests(loader.loadTestsFromModule(legacy))
    return tests
if __name__=='__main__':unittest.main()
