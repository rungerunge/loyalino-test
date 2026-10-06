"""Complete fictional Mach-O capacity tests. No IPA, actual key, provider or history."""
import base64, hashlib, importlib.util, json, plistlib, struct, sys, unittest
from pathlib import Path

ROOT = Path(__file__).parent
PARENT = ROOT.parent / 'ios16-protected-github-macos-runtime-config-20261006'
sys.path.insert(0, str(ROOT))
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
native = load('capacity_native', ROOT / 'native-audit.py')
old_bytes = load('capacity_original_byte_controls', ROOT / 'native-byte.test.py')
parent_tests = load('capacity_frozen_parent_controls', PARENT / 'runtime-config.test.py')

class SignatureCapacity(unittest.TestCase):
    def fixture(self, reserve=0, extra=0):
        info = plistlib.dumps({'fixture': True})
        resources = plistlib.dumps({'files2': {}})
        ent = plistlib.dumps({'com.apple.developer.team-identifier': native.TEAM,
                             'application-identifier': native.TEAM + '.' + native.BUNDLE,
                             'get-task-allow': False, 'aps-environment': 'production',
                             'com.apple.developer.associated-domains': ['applinks:nevermonday.dk']})
        wrap = lambda magic, body: struct.pack('>II', magic, 8 + len(body)) + body
        xml, der = wrap(0xfade7171, ent), wrap(0xfade7172, b'fictional-DER')
        part = bytearray(4096)
        struct.pack_into('<IIIIIIII', part, 0, 0xfeedfacf, 0x100000c, 0, 2, 1, 16, 0, 0)
        ident, team, header = native.BUNDLE.encode() + b'\0', native.TEAM.encode() + b'\0', 88
        teamoff = header + len(ident)
        hashoff = teamoff + len(team) + 7 * 32
        cd = bytearray(hashoff + 32)
        struct.pack_into('>IIIIIIIII', cd, 0, 0xfade0c02, len(cd), 0x20200, 0,
                         hashoff, header, 7, 1, 4096)
        struct.pack_into('>BBBB', cd, 36, 32, 2, 0, 12)
        struct.pack_into('>I', cd, 48, teamoff)
        cd[header:header + len(ident)], cd[teamoff:teamoff + len(team)] = ident, team
        blobs = {0: cd, 5: xml, 7: der, 65536: wrap(0xfade0b01, b'fictional-CMS')}
        for n in range(extra):
            blobs[100 + n] = wrap(0xfade0b01, b'fictional-optional-slot')
        length = 12 + len(blobs) * 8 + sum(len(b) for b in blobs.values())
        # Capacity changes the signed load-command page; sign AFTER writing it.
        struct.pack_into('<IIII', part, 32, 0x1d, 16, 4096, length + reserve)
        for slot, body in [(1, info), (3, resources), (5, xml), (7, der)]:
            cd[hashoff - slot * 32:hashoff - (slot - 1) * 32] = hashlib.sha256(body).digest()
        cd[hashoff:hashoff + 32] = hashlib.sha256(part).digest()
        code = bytearray(struct.pack('>III', 0xfade0cc0, length, len(blobs)))
        at, offsets = 12 + len(blobs) * 8, {}
        for slot, body in blobs.items():
            offsets[slot] = at
            code += struct.pack('>II', slot, at)
            at += len(body)
        for body in blobs.values():
            code += body
        return bytes(part + code + bytes(reserve)), info, resources, length, offsets

    def result(self, reserve=0, extra=0):
        data, info, resources, _, _ = self.fixture(reserve, extra)
        return native.executable(data, info, resources)

    def refuse(self, data, info, resources):
        with self.assertRaises((ValueError, struct.error, plistlib.InvalidFileException)):
            native.executable(data, info, resources)

    def test_exact_unpadded_legacy_signature_accepts(self):
        result = self.result()
        self.assertEqual(result['codeDirectories'], 1)
        self.assertEqual(set(result), {'codeDirectory', 'cms', 'codeDirectories'})
        self.assertEqual(base64.b64decode(result['cms']), b'fictional-CMS')

    def test_sixteen_zero_capacity_bytes_accept(self):
        data, info, resources, length, _ = self.fixture(16)
        self.assertEqual(len(data) - 4096 - length, 16)
        self.assertEqual(native.executable(data, info, resources)['codeDirectories'], 1)

    def test_large_cms_reserve_is_not_limited_to_alignment_slack(self):
        data, info, resources, length, _ = self.fixture(18000)
        self.assertGreater(len(data) - 4096 - length, 15)
        self.assertEqual(native.executable(data, info, resources)['codeDirectories'], 1)

    def test_aligned_reserved_capacity_accepts(self):
        _, _, _, length, _ = self.fixture()
        reserve = ((length + 18000 + 15) // 16) * 16 - length
        data, info, resources, _, _ = self.fixture(reserve)
        self.assertEqual((len(data) - 4096) % 16, 0)
        self.assertEqual(native.executable(data, info, resources)['codeDirectories'], 1)

    def test_count_32_boundary_keeps_original_slots_and_hashes(self):
        self.assertEqual(self.result(16, 28)['codeDirectories'], 1)

    def test_first_nonzero_capacity_byte_refuses(self):
        data, info, resources, length, _ = self.fixture(18000)
        value = bytearray(data); value[4096 + length] = 1
        self.refuse(bytes(value), info, resources)

    def test_last_nonzero_capacity_byte_refuses(self):
        data, info, resources, _, _ = self.fixture(18000)
        value = bytearray(data); value[-1] = 1
        self.refuse(bytes(value), info, resources)

    def test_second_hidden_superblob_in_capacity_refuses(self):
        data, info, resources, length, _ = self.fixture(18000)
        value = bytearray(data)
        value[4096 + length:4096 + length + 12] = struct.pack('>III', 0xfade0cc0, 12, 0)
        self.refuse(bytes(value), info, resources)

    def test_wrong_superblob_magic_refuses(self):
        data, info, resources, _, _ = self.fixture(16)
        value = bytearray(data); struct.pack_into('>I', value, 4096, 0)
        self.refuse(bytes(value), info, resources)

    def test_zero_count_refuses(self):
        data, info, resources, _, _ = self.fixture(16)
        value = bytearray(data); struct.pack_into('>I', value, 4104, 0)
        self.refuse(bytes(value), info, resources)

    def test_count_33_refuses(self):
        data, info, resources, _, _ = self.fixture(16)
        value = bytearray(data); struct.pack_into('>I', value, 4104, 33)
        self.refuse(bytes(value), info, resources)

    def test_declared_length_below_header_or_index_refuses(self):
        data, info, resources, _, _ = self.fixture(16)
        for length in [0, 11, 43]:
            value = bytearray(data); struct.pack_into('>I', value, 4100, length)
            self.refuse(bytes(value), info, resources)

    def test_declared_length_beyond_capacity_refuses(self):
        data, info, resources, _, _ = self.fixture(16)
        for length in [len(data) - 4096 + 1, 0xffffffff]:
            value = bytearray(data); struct.pack_into('>I', value, 4100, length)
            self.refuse(bytes(value), info, resources)

    def test_subblob_cannot_claim_capacity_outside_declared_length(self):
        data, info, resources, length, offsets = self.fixture(18000)
        value = bytearray(data)
        struct.pack_into('>I', value, 4096 + offsets[0] + 4, length - offsets[0] + 1)
        self.refuse(bytes(value), info, resources)

    def test_index_offset_into_zero_capacity_refuses(self):
        data, info, resources, length, _ = self.fixture(18000)
        value = bytearray(data); struct.pack_into('>I', value, 4096 + 16, length)
        self.refuse(bytes(value), info, resources)

    def test_index_offset_inside_index_refuses(self):
        data, info, resources, _, _ = self.fixture(16)
        value = bytearray(data); struct.pack_into('>I', value, 4096 + 16, 12)
        self.refuse(bytes(value), info, resources)

    def test_duplicate_slot_and_overlapping_spans_refuse(self):
        data, info, resources, _, offsets = self.fixture(16)
        duplicate = bytearray(data); struct.pack_into('>I', duplicate, 4096 + 20, 0)
        overlap = bytearray(data); struct.pack_into('>I', overlap, 4096 + 24, offsets[0])
        self.refuse(bytes(duplicate), info, resources)
        self.refuse(bytes(overlap), info, resources)

    def test_truncated_or_outside_lc_extent_tail_refuses(self):
        data, info, resources, _, _ = self.fixture(16)
        for value in [data[:-1], data + b'\0', data + b'nonzero']:
            self.refuse(value, info, resources)

    def test_duplicate_lc_signature_refuses(self):
        data, info, resources, _, _ = self.fixture(16)
        value = bytearray(data)
        struct.pack_into('<II', value, 16, 2, 32)
        value[48:64] = value[32:48]
        self.refuse(bytes(value), info, resources)

    def test_padded_signature_still_binds_entire_signed_page(self):
        data, info, resources, _, _ = self.fixture(18000)
        value = bytearray(data); value[100] ^= 1
        self.refuse(bytes(value), info, resources)

    def test_padded_signature_still_binds_info_and_resources(self):
        data, info, resources, _, _ = self.fixture(18000)
        for changed_info, changed_resources in [(b'changed', resources), (info, b'changed')]:
            self.refuse(data, changed_info, changed_resources)

    def test_code_directory_magic_and_team_still_required(self):
        data, info, resources, _, offsets = self.fixture(18000)
        bad_magic = bytearray(data); struct.pack_into('>I', bad_magic, 4096 + offsets[0], 0)
        bad_team = bytearray(data)
        teamoff = struct.unpack_from('>I', data, 4096 + offsets[0] + 48)[0]
        bad_team[4096 + offsets[0] + teamoff] ^= 1
        self.refuse(bytes(bad_magic), info, resources)
        self.refuse(bytes(bad_team), info, resources)

    def test_cms_wrapper_magic_still_required(self):
        data, info, resources, _, offsets = self.fixture(18000)
        value = bytearray(data); struct.pack_into('>I', value, 4096 + offsets[65536], 0)
        self.refuse(bytes(value), info, resources)

    def test_signature_shape_projects_only_closed_scalars(self):
        data, _, _, length, _ = self.fixture(18000)
        code = bytearray(data[4096:]); code[length] = 1
        try:
            native.signature_capacity(bytes(code))
        except ValueError as error:
            value = native.failure_projection(error)
        self.assertFalse(value['nativeAuditVerified'])
        self.assertTrue(value['diagnosticOnly'])
        self.assertEqual(value['exceptionType'], 'ValueError')
        shape = value['signatureCapacity']
        self.assertEqual(len(shape), 11)
        self.assertEqual(shape['remainingCapacityBytes'], 18000)
        self.assertTrue(shape['magicMatches'])
        self.assertFalse(shape['remainingCapacityZero'])
        self.assertTrue(all(type(item) in [bool, int] for item in shape.values()))
        for forbidden in ['fictional-CMS', native.TEAM, native.BUNDLE, 'signature_capacity_shape']:
            self.assertNotIn(forbidden, json.dumps(value))

    def test_unreadable_header_has_finite_diagnostic_only(self):
        try:
            native.signature_capacity(b'PRIVATE')
        except ValueError as error:
            value = native.failure_projection(error)
        self.assertFalse(value['signatureCapacity']['headerReadable'])
        self.assertFalse(value['nativeAuditVerified'])
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_unknown_or_malformed_attached_diagnostics_are_suppressed(self):
        error = ValueError('PRIVATE')
        self.assertIsNone(native.signature_failure_shape(error))
        error.signature_capacity_shape = {'private': 'PRIVATE'}
        self.assertIsNone(native.signature_failure_shape(error))
        self.assertNotIn('signatureCapacity', native.failure_projection(error))

    def test_diagnostic_class_and_string_never_rescue_or_leak(self):
        class PrivateError(ValueError):
            def __str__(self): raise AssertionError('never stringify')
        error = PrivateError('PRIVATE')
        error.signature_capacity_shape = {}
        value = native.failure_projection(error)
        self.assertEqual(value['exceptionType'], 'OtherSuppressed')
        self.assertNotIn('signatureCapacity', value)
        self.assertNotIn('PRIVATE', json.dumps(value))

def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(old_bytes))
    tests.addTests(loader.loadTestsFromModule(parent_tests))
    return tests

if __name__ == '__main__':
    unittest.main()
