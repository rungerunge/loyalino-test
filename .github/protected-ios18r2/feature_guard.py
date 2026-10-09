import plistlib

DA_CAMERA = 'NeverMonday bruger kameraet til at scanne QR-koden på dit skrabekort. Ingen billeder gemmes eller sendes.'
EN_CAMERA = 'NeverMonday uses the camera to scan your scratch card’s QR code. No images are saved or sent.'
BENEFIT_MARKERS = (b'scratch-screen', b'scratch-camera', b'scratch-preview', b'scratch-confirm', b'scratch-claim-retry', b'scratch-code', b'scratch-success', b'scratch-rewards', b'store-credit-summary', b'store-credit-balance', b'store-credit-retry', b'/scratch-cards/preview', b'/scratch-cards/claim', b'/store-credit', b'LSC1:')

def camera_locale_proof(info, read, verified):
    result = {'cameraPurposeDanishExact': info.get('NSCameraUsageDescription') == DA_CAMERA,
              'localizedCameraPurposeResourcesBound': all(p in verified for p in ('da.lproj/InfoPlist.strings', 'en.lproj/InfoPlist.strings'))}
    for locale, expected in [('da', DA_CAMERA), ('en', EN_CAMERA)]:
        values = plistlib.loads(read(locale + '.lproj/InfoPlist.strings'))
        result[locale + 'CameraPurposeExact'] = values.get('NSCameraUsageDescription') == expected
    return result

def financial_info_proof(privacy):
    entries = [d for d in privacy.get('NSPrivacyCollectedDataTypes', []) if d.get('NSPrivacyCollectedDataType') == 'NSPrivacyCollectedDataTypeOtherFinancialInfo']
    return len(entries) == 1 and entries[0].get('NSPrivacyCollectedDataTypeLinked') is True and entries[0].get('NSPrivacyCollectedDataTypeTracking') is False and entries[0].get('NSPrivacyCollectedDataTypePurposes') == ['NSPrivacyCollectedDataTypePurposeAppFunctionality']

def benefit_marker_proof(bundle, verified):
    count = sum(marker in bundle for marker in BENEFIT_MARKERS)
    return {'compiledMemberBenefitsMarkerCount': count, 'compiledMemberBenefitsMarkersPresent': count == len(BENEFIT_MARKERS) and 'main.jsbundle' in verified}
