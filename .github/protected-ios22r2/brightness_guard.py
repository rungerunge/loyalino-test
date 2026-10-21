"""Five signed compiled literals; this does not measure native brightness/races."""
SOURCE = '297ca675225b3aa0f361395b99a998ced3a3afe9'
MARKERS = (
    b'restoreSystemBrightnessAsync', b'getBrightnessAsync',
    b'setBrightnessAsync', b'whenIdle', b'setForeground',
)


def brightness_marker_proof(bundle, verified, artifact_source):
    signed = 'main.jsbundle' in verified
    count = sum(marker in bundle for marker in MARKERS)
    return {
        'compiledBrightnessMarkerCount': count,
        'compiledBrightnessMarkersPresent': signed and count == len(MARKERS),
        'brightnessSourceCommit': SOURCE,
        'brightnessSourceAssociationExact': signed and count == len(MARKERS) and artifact_source == SOURCE,
        'brightnessEvidenceScope': 'SIGNED_COMPILED_MARKERS_AND_EXACT_EAS_GIT_COMMIT',
    }
