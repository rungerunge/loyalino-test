"""Five signed compiled literals; this does not measure native brightness/races."""
SOURCE = '7f4e28ad4f70737f42da6caf9d68dcb5077a6aef'
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
