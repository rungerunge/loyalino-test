import hashlib
import json
import re
from pathlib import Path

TARGET_ID = 'PENDING_ROOT_IOS_JOB'
TARGET_SOURCE = 'a59e987d45d59ae6e6cdc53620c1640495cd4626'
TARGET_OUTPUT = 'C:/Users/runge/Desktop/nevermonday app/release/nevermonday-ios-production-PENDING_ROOT_IOS_PREFIX.ipa'
ROOT = Path(__file__).resolve().parent
MIN_BYTES = 10 * 1024 * 1024
MAX_BYTES = 200 * 1024 * 1024

def assert_receipt(receipt, data, minimum=MIN_BYTES, maximum=MAX_BYTES):
    expected = {'id': TARGET_ID, 'source': TARGET_SOURCE, 'platform': 'IOS',
                'appVersion': '1.0.0', 'appBuildVersion': '15', 'bundle': 'dk.nevermonday.app',
                'output': TARGET_OUTPUT, 'exactFinishedLineage': True, 'downloadVerified': True}
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError('EXACT_BUILD15_RECEIPT_REJECTED')
    digest = hashlib.sha256(data).hexdigest().upper()
    if not minimum <= len(data) <= maximum or not data.startswith(bytes.fromhex('504b0304')):
        raise ValueError('ARTIFACT_SIZE_OR_MAGIC_REJECTED')
    if receipt.get('bytes') != len(data) or receipt.get('sha256') != digest:
        raise ValueError('ARTIFACT_IMMUTABILITY_REJECTED')
    return receipt

def assert_pins():
    if not re.fullmatch(r'[a-f0-9]{40}', TARGET_SOURCE) or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', TARGET_ID) or 'PENDING' in TARGET_OUTPUT:
        raise ValueError('REPLACEMENT_PINS_NOT_FROZEN')

def guard_artifact():
    assert_pins()
    receipt = json.loads((ROOT / 'artifact-download-sanitized.json').read_text(encoding='utf-8'))
    ipa = Path(TARGET_OUTPUT)
    assert_receipt(receipt, ipa.read_bytes())
    return ipa, receipt

def verify_resource_hashes(files, app, read_resource, archive_names):
    verified = set()
    mismatches = nested = 0
    names = set(archive_names)
    for name, entry in files.items():
        if not isinstance(entry, dict):
            continue
        hashes = [(key, algorithm) for key, algorithm in [('hash', 'sha1'), ('hash2', 'sha256')] if key in entry]
        if not hashes:
            nested += int('cdhash' in entry)
            continue
        if app + name not in names:
            mismatches += int(not entry.get('optional'))
            continue
        data = read_resource(app + name)
        if all(hashlib.new(algorithm, data).digest() == entry[key] for key, algorithm in hashes):
            verified.add(name)
        else:
            mismatches += 1
    return verified, mismatches, nested

def otp_marker_evidence(bundle):
    # Strings prove inclusion in the signed compiled bundle, never focus/AutoFill behavior.
    markers = (b'code-input-target', b'code-input-digits')
    return sum(marker in bundle for marker in markers)


def wallet_marker_evidence(bundle):
    markers = (b"wallet-pass-screen", b"wallet-open", b"wallet-save-consent", b"wallet-updates", b"wallet-marketing", b"wallet-location")
    return sum(marker in bundle for marker in markers)


CART_CONTEXT = b'@inContext(country: $country, language: $language, visitorConsent: {analytics: false, marketing: false, preferences: true, saleOfData: false})'


def require_cart_consent_evidence(compiled_bundle, verified_resources):
    # Inclusion evidence from the actual signed main bundle only, never source/config evidence.
    # This does not establish runtime consent, native pixel behavior or absence of tracking.
    if 'main.jsbundle' not in verified_resources or CART_CONTEXT not in compiled_bundle:
        raise ValueError('SIGNED_COMPILED_CART_CONTEXT_REJECTED')
    return True
