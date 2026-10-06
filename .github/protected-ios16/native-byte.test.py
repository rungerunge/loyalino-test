"""Synthetic independent Mach-O regression. No IPA/actual source input."""
import hashlib, plistlib, struct, unittest
import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('native_audit',Path(__file__).with_name('native-audit.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
executable=module.executable
class Bytes(unittest.TestCase):
    def fixture(self):
        info=plistlib.dumps({'fixture':True});resources=plistlib.dumps({'files2':{}})
        ent=plistlib.dumps({'com.apple.developer.team-identifier':'XNPLDX9MHP','application-identifier':'XNPLDX9MHP.dk.nevermonday.app','get-task-allow':False,'aps-environment':'production','com.apple.developer.associated-domains':['applinks:nevermonday.dk']})
        wrap=lambda magic,b:struct.pack('>II',magic,8+len(b))+b
        xml=wrap(0xfade7171,ent);der=wrap(0xfade7172,b'fake-DER')
        part=bytearray(4096);struct.pack_into('<IIIIIIII',part,0,0xfeedfacf,0x100000c,0,2,1,16,0,0)
        team=b'XNPLDX9MHP\0'; header=88; ident=b'dk.nevermonday.app\0';teamoff=header+len(ident);hashoff=teamoff+len(team)+7*32
        cd=bytearray(hashoff+32);struct.pack_into('>IIIIIIIII',cd,0,0xfade0c02,len(cd),0x20200,0,hashoff,header,7,1,4096);struct.pack_into('>BBBB',cd,36,32,2,0,12);struct.pack_into('>I',cd,48,teamoff);cd[header:header+len(ident)]=ident;cd[teamoff:teamoff+len(team)]=team
        blobs={0:cd,5:xml,7:der,65536:wrap(0xfade0b01,b'fake-CMS')};sigsize=12+len(blobs)*8+sum(len(b) for b in blobs.values());struct.pack_into('<IIII',part,32,0x1d,16,4096,sigsize)
        for slot,b in [(1,info),(3,resources),(5,xml),(7,der)]:cd[hashoff-slot*32:hashoff-(slot-1)*32]=hashlib.sha256(b).digest()
        cd[hashoff:hashoff+32]=hashlib.sha256(part).digest();code=bytearray(struct.pack('>III',0xfade0cc0,sigsize,len(blobs)));at=12+len(blobs)*8
        for slot,b in blobs.items():code+=struct.pack('>II',slot,at);at+=len(b)
        for b in blobs.values():code+=b
        return bytes(part+code),info,resources
    def test_real_page_and_special_slot_algorithms(self):
        b,i,r=self.fixture();self.assertEqual(executable(b,i,r)['codeDirectories'],1)
    def test_tampered_page_refuses(self):
        b,i,r=self.fixture();a=bytearray(b);a[100]^=1
        with self.assertRaises(ValueError):executable(bytes(a),i,r)
    def test_info_and_resources_bound(self):
        b,i,r=self.fixture()
        for x,y in [(b'changed',r),(i,b'changed')]:
            with self.assertRaises(ValueError):executable(b,x,y)
    def test_missing_or_extra_executable_signature_refuses(self):
        b,i,r=self.fixture()
        for value in [b[:-1],b+b'extra',b'not Mach-O']:
            with self.assertRaises((ValueError,struct.error)):executable(value,i,r)
    def test_current_cart_query_markers_and_exact_source_associations(self):
        bundle=b'\0'.join(module.CART_MARKERS+module.QUERY_MARKERS)
        result=module.current_fixes(bundle,{'main.jsbundle'})
        self.assertTrue(result['cartRecoveryCompiledMarkersVerified'])
        self.assertTrue(result['queryReconnectCompiledMarkersVerified'])
        self.assertFalse(result['nativeRecoveryBehaviorVerified'])
        self.assertEqual(result['nativeSource'],'6aa3fc0fed9ccdd929533632ed1edef2e1f8cde5')
    def test_each_current_compiled_marker_is_required(self):
        values=set(module.CART_MARKERS+module.QUERY_MARKERS)
        for marker in values:
            with self.assertRaises(ValueError):module.current_fixes(b'\0'.join(values-{marker}),{'main.jsbundle'})
    def test_unsigned_compiled_marker_vector_refuses(self):
        with self.assertRaises(ValueError):module.current_fixes(b'\0'.join(module.CART_MARKERS+module.QUERY_MARKERS),set())
if __name__=='__main__':unittest.main()
