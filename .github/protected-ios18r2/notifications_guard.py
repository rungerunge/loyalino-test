"""Pure inbox and privacy declarations. No provider/native UI claim."""
INBOX_MARKERS = (b'/notifications', b'/notifications/', b'readThrough', b'Beskeder',
                 b'Open notifications', b'Mark all as read', b'notifications-mark-all',
                 b'notifications-list', b'notifications-more', b'notifications-loading',
                 b'useRefreshNotificationInbox')
EXPECTED_TYPES = frozenset(('EmailAddress', 'Name', 'PhoneNumber', 'PhysicalAddress',
                           'PaymentInfo', 'OtherFinancialInfo', 'PurchaseHistory',
                           'UserID', 'DeviceID', 'OtherDataTypes', 'ProductInteraction'))
PREFIX = 'NSPrivacyCollectedDataType'
FUNCTIONALITY = PREFIX + 'PurposeAppFunctionality'
ADVERTISING = PREFIX + 'PurposeDeveloperAdvertising'


def inbox_marker_proof(bundle, verified):
    count = sum(marker in bundle for marker in INBOX_MARKERS)
    return {'compiledInboxMarkerCount': count,
            'compiledInboxMarkersPresent': count == len(INBOX_MARKERS) and 'main.jsbundle' in verified}


def inbox_privacy_proof(privacy):
    declarations = privacy.get('NSPrivacyCollectedDataTypes', [])
    valid = isinstance(declarations, list) and all(isinstance(d, dict) for d in declarations)
    exact = valid and len(declarations) == 11 and {d.get(PREFIX, '').removeprefix(PREFIX) for d in declarations} == EXPECTED_TYPES
    linked = valid and bool(declarations) and all(d.get(PREFIX + 'Linked') is True and d.get(PREFIX + 'Tracking') is False for d in declarations)
    purposes = valid and bool(declarations) and all(
        isinstance(d.get(PREFIX + 'Purposes'), list) and len(d[PREFIX + 'Purposes']) == len(set(d[PREFIX + 'Purposes'])) and
        set(d[PREFIX + 'Purposes']) == ({FUNCTIONALITY, ADVERTISING} if d.get(PREFIX) in {PREFIX + 'EmailAddress', PREFIX + 'DeviceID', PREFIX + 'UserID', PREFIX + 'OtherDataTypes'} else {FUNCTIONALITY})
        for d in declarations)
    return {'collectedDataTypeCount': len(declarations) if valid else 0,
            'elevenExpectedCollectedDataTypesExact': exact,
            'allCollectedDataLinkedAndUntracked': linked,
            'collectedDataPurposesMatch': purposes,
            'inboxProductInteractionDeclarationExact': exact and linked and purposes}
