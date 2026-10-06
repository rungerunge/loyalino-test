"""Pure signed-runtime-config predicates. No IPA, auth, provider or protected history."""
import importlib.util,json,unittest
from pathlib import Path
root=Path(__file__).parent
spec=importlib.util.spec_from_file_location('current_native',root/'native-audit.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
legacy_spec=importlib.util.spec_from_file_location('current_diagnostics',root/'audit-diagnostic.test.py')
legacy=importlib.util.module_from_spec(legacy_spec);legacy_spec.loader.exec_module(legacy)

class RuntimeConfig(unittest.TestCase):
    def fixture(self):
        value={'sdkVersion':'57.0.0','extra':{'apiBase':native.API.decode(),'eas':{'projectId':native.RUNTIME_PROJECT}}}
        return value,json.dumps(value).encode(),{'main.jsbundle',native.RUNTIME_CONFIG}
    def proof(self,raw=None,bundle=None,name=None,verified=None,more=None,prefix=''):
        _,good,signed=self.fixture()
        candidates=[(prefix+(name or native.RUNTIME_CONFIG),good if raw is None else raw)]
        if more:candidates+=more
        return native.bundle_runtime_proof(native.HERMES_MAGIC+b'fictional-bytecode' if bundle is None else bundle,candidates,signed if verified is None else verified,prefix)
    def test_manifest_only_api_and_no_js_literal_accepts(self):
        bundle=native.HERMES_MAGIC+b'fictional-bytecode-without-endpoint'
        self.assertNotIn(native.API,bundle);self.assertTrue(self.proof(bundle=bundle))
    def test_expected_api_in_js_never_overrides_wrong_manifest(self):
        value,_,_=self.fixture();value['extra']['apiBase']='https://wrong.invalid/api/mobile/v1'
        with self.assertRaises(ValueError):self.proof(raw=json.dumps(value).encode(),bundle=native.HERMES_MAGIC+native.API)
    def test_actual_archive_prefix_is_required(self):
        self.assertTrue(self.proof(prefix='Payload/Fictional.app/'))
        _,raw,signed=self.fixture()
        with self.assertRaises(ValueError):native.bundle_runtime_proof(native.HERMES_MAGIC,[(native.RUNTIME_CONFIG,raw)],signed,'Payload/Fictional.app/')
    def test_unsigned_config_refuses(self):
        with self.assertRaises(ValueError):self.proof(verified={'main.jsbundle'})
    def test_absent_config_refuses(self):
        with self.assertRaises(ValueError):native.runtime_config_proof([],set())
    def test_duplicate_exact_config_refuses(self):
        _,raw,_=self.fixture()
        with self.assertRaises(ValueError):self.proof(more=[(native.RUNTIME_CONFIG,raw)])
    def test_competing_unsigned_config_refuses(self):
        _,raw,_=self.fixture()
        with self.assertRaises(ValueError):self.proof(more=[('Other.bundle/app.config',raw)])
    def test_competing_wrong_prefix_refuses(self):
        _,raw,_=self.fixture()
        with self.assertRaises(ValueError):self.proof(more=[('Frameworks/EXConstants.bundle/app.config',raw)])
    def test_wrong_only_path_refuses(self):
        with self.assertRaises(ValueError):self.proof(name='Other.bundle/app.config')
    def test_malformed_json_refuses(self):
        with self.assertRaises(json.JSONDecodeError):self.proof(raw=b'{malformed}')
    def test_invalid_utf8_refuses(self):
        with self.assertRaises(UnicodeDecodeError):self.proof(raw=b'\xff')
    def test_duplicate_top_level_key_refuses(self):
        _,raw,_=self.fixture();raw=raw[:-1]+b',"sdkVersion":"57.0.0"}'
        with self.assertRaises(ValueError):self.proof(raw=raw)
    def test_duplicate_nested_api_key_refuses(self):
        raw=b'{"sdkVersion":"57.0.0","extra":{"apiBase":"https://wrong.invalid","apiBase":"'+native.API+b'","eas":{"projectId":"'+native.RUNTIME_PROJECT.encode()+b'"}}}'
        with self.assertRaises(ValueError):self.proof(raw=raw)
    def test_nonstandard_json_constant_refuses(self):
        _,raw,_=self.fixture();raw=raw[:-1]+b',"unrelated":NaN}'
        with self.assertRaises(ValueError):self.proof(raw=raw)
    def test_nonobject_json_refuses(self):
        for raw in [b'null',b'[]',b'1',b'"text"']:
            with self.assertRaises(ValueError):self.proof(raw=raw)
    def test_wrong_or_missing_sdk_refuses(self):
        for sdk in ['56.0.0',None,57]:
            value,_,_=self.fixture();value['sdkVersion']=sdk
            with self.assertRaises(ValueError):self.proof(raw=json.dumps(value).encode())
    def test_wrong_or_missing_project_refuses(self):
        for project in ['foreign',None,True]:
            value,_,_=self.fixture();value['extra']['eas']['projectId']=project
            with self.assertRaises(ValueError):self.proof(raw=json.dumps(value).encode())
    def test_wrong_extra_and_eas_shape_refuses(self):
        for key in ['extra','eas']:
            value,_,_=self.fixture()
            if key=='extra':value['extra']=[]
            else:value['extra']['eas']=[]
            with self.assertRaises(ValueError):self.proof(raw=json.dumps(value).encode())
    def test_trailing_slash_and_foreign_runtime_url_refuse(self):
        for url in [native.API.decode()+'/', 'https://api.nevermonday.dk/api/mobile/v1']:
            value,_,_=self.fixture();value['extra']['apiBase']=url
            with self.assertRaises(ValueError):self.proof(raw=json.dumps(value).encode())
    def test_forbidden_js_url_refuses_with_correct_manifest(self):
        with self.assertRaises(ValueError):self.proof(bundle=native.HERMES_MAGIC+b'https://api.nevermonday.dk/api/mobile/v1')
    def test_bad_and_plain_javascript_bytecode_refuse(self):
        for bundle in [b'',b'plain JavaScript',b'notmagic'+native.API,native.HERMES_MAGIC[:7]]:
            with self.assertRaises(ValueError):self.proof(bundle=bundle)
    def test_config_empty_and_size_bound_refuse(self):
        for raw in [b'',b' '*65537]:
            with self.assertRaises(ValueError):self.proof(raw=raw)
    def test_failure_projection_only_closed_source_locations(self):
        try:self.proof(bundle=b'PRIVATE bytecode')
        except Exception as error:
            value=native.failure_projection(error)
        self.assertEqual(value['exceptionType'],'ValueError');self.assertTrue(value['sourceFrames'])
        self.assertTrue(all(v['file']=='native-audit.py' for v in value['sourceFrames']))
        self.assertNotIn('PRIVATE',json.dumps(value));self.assertNotIn('Payload',json.dumps(value))
    def test_all_archive_candidates_reach_proof_before_unsigned_filter(self):
        text=(root/'native-audit.py').read_text()
        self.assertIn("candidates = [name for name in names if name.endswith('app.config')]",text)
        self.assertIn("archive_runtime_proof(bundle, names, verified, app, z.getinfo, z.read)",text)
        self.assertNotIn("for n in verified if n.endswith('app.config')",text.split('def failure_projection')[0].split("bundle=z.read(app+'main.jsbundle')")[1].split('require(otp')[0])

    def test_archive_unique_signed_candidate_reads_once(self):
        from types import SimpleNamespace
        _,raw,signed=self.fixture();name='Payload/Fictional.app/'+native.RUNTIME_CONFIG;calls=[]
        result=native.archive_runtime_proof(native.HERMES_MAGIC,[name,'Payload/Fictional.app/main.jsbundle'],signed,'Payload/Fictional.app/',lambda n:SimpleNamespace(file_size=len(raw)),lambda n:(calls.append(n),raw)[1])
        self.assertTrue(result);self.assertEqual(calls,[name])
    def test_archive_extra_candidate_refuses_before_info_or_read(self):
        name='Payload/Fictional.app/'+native.RUNTIME_CONFIG
        def forbidden(_):self.fail('candidate read before ambiguity refusal')
        with self.assertRaises(ValueError):native.archive_runtime_proof(native.HERMES_MAGIC,[name,'Other/app.config'],{native.RUNTIME_CONFIG},'Payload/Fictional.app/',forbidden,forbidden)
    def test_archive_unsigned_or_wrong_path_refuses_before_read(self):
        from types import SimpleNamespace
        def forbidden(_):self.fail('unsigned or alternate read')
        for name,signed in [('Payload/Fictional.app/'+native.RUNTIME_CONFIG,set()),('Other/'+native.RUNTIME_CONFIG,{native.RUNTIME_CONFIG})]:
            with self.assertRaises(ValueError):native.archive_runtime_proof(native.HERMES_MAGIC,[name],signed,'Payload/Fictional.app/',lambda n:SimpleNamespace(file_size=1),forbidden)
    def test_archive_oversized_candidate_refuses_before_decompression(self):
        from types import SimpleNamespace
        name='Payload/Fictional.app/'+native.RUNTIME_CONFIG
        def forbidden(_):self.fail('oversized decompression')
        for size in [0,65537,True]:
            with self.assertRaises(ValueError):native.archive_runtime_proof(native.HERMES_MAGIC,[name],{native.RUNTIME_CONFIG},'Payload/Fictional.app/',lambda n:SimpleNamespace(file_size=size),forbidden)

    def test_whole_audit_bad_candidate_precedes_resource_validator_and_any_read(self):
        from types import SimpleNamespace
        expected='Payload/Fictional.app/'+native.RUNTIME_CONFIG
        class FakePath:
            def __init__(self,_):pass
            def read_bytes(self):return b'PK\x03\x04'+b'0'*999996
        class Zip:
            def __init__(self,names,size):self.names=names;self.size=size
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def namelist(self):return self.names
            def infolist(self):return [SimpleNamespace(file_size=self.size if n==expected else 10) for n in self.names]
            def getinfo(self,n):return SimpleNamespace(file_size=self.size)
            def read(self,n):calls.append('read');raise AssertionError('archive read before preflight')
        original=(native.Path,native.zipfile.ZipFile,native.verify_resource_hashes)
        try:
            native.Path=FakePath
            def resources(*_):calls.append('resources');raise AssertionError('resource validator before preflight')
            native.verify_resource_hashes=resources
            for config_names,size in [([expected,'Other/app.config'],10),([expected],65537),(['Other/app.config'],10)]:
                calls=[];native.zipfile.ZipFile=lambda _,ns=config_names,sz=size:Zip(['Payload/Fictional.app/Info.plist',*ns],sz)
                with self.assertRaises(ValueError):native.audit('FICTIONAL.ipa')
                self.assertEqual(calls,[])
        finally:native.Path,native.zipfile.ZipFile,native.verify_resource_hashes=original

def load_tests(loader,tests,pattern):
    tests.addTests(loader.loadTestsFromModule(legacy))
    return tests
if __name__=='__main__':unittest.main()
