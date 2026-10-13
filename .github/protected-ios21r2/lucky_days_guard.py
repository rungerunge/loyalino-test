"""Pure checks of signed compiled inclusion and Expo configuration, never device behavior."""
import json

MARKERS = ('/scratch-card-history', 'scratch-history-list', 'scratch-history-loading',
           'scratch-history-more', 'scratch-history-more-retry', 'scratch-receipt-open-',
           'scratch-receipt-recover-', 'scratch-prize-details', 'itemPolicy',
           'minimumPurchase', 'expiresInDays', 'instructions', 'manual_review', 'scratch_card')
# Derived from exact613aef4's committed Expo57.0.26 lock entry by prepare.cjs.
SDK = '57.0.0'
EXPO_PACKAGE = '57.0.26'
PROJECT = 'adf6c486-4d81-4e19-b6b7-25e5b4ca1064'
API = 'https://backend-production-d356.up.railway.app/api/mobile/v1'


def lucky_days_marker_proof(bundle, verified):
    count = sum(marker.encode() in bundle for marker in MARKERS)
    return {'compiledScratchReceiptMarkerCount': count,
            'compiledScratchReceiptMarkersPresent': count == len(MARKERS) and 'main.jsbundle' in verified}


def signed_sdk_proof(configs, verified):
    accepted = []
    for name, raw in configs:
        if name not in verified:
            continue
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            continue
        # Expo's signed app.config must explicitly contain the derived SDK.
        # A missing value, other major or guessed/default SDK never passes.
        if not isinstance(value, dict):
            continue
        extra = value.get('extra')
        if not isinstance(extra, dict) or extra.get('apiBase') != API:
            continue
        accepted.append(value.get('sdkVersion') == SDK and
                        isinstance(extra.get('eas'), dict) and extra['eas'].get('projectId') == PROJECT)
    return {'embeddedExpoSdkVersionExact': bool(accepted) and all(accepted),
            'expectedExpoSdkVersion': SDK, 'lockedExpoPackageVersion': EXPO_PACKAGE,
            'signedExpoConfigCount': len(accepted)}
