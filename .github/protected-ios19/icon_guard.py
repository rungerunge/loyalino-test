"""Bounded PNG/CgBI decoding and signed native icon identity; no launcher claim.

The 854 stable sample positions come from the original, deterministic 1024 icon,
excluding an eight-pixel neighbourhood around antialias boundaries. This allows
Apple's PNG optimization/resampling while rejecting the previous monogram, wrong
colour, padding or silhouette. Native PNG bytes must be CodeResources verified.
Assets.car is bound as a signed archive resource, not decoded or claimed as UI.
"""
import hashlib
import re
import struct
import zlib

INPUT_ICON_SHA256 = '9d5c407c47a01dfa43981aa19222f553dfdb3844404864be792520e3344a8122'
ORIGINAL_CIRCLE_SHA256 = 'bfb7a24e89fe5e2f774858b2169f9ec3f244f8dacf12bdd419d0d1b45b3b7b99'
BROWN = (56, 38, 31)
IVORY = (248, 244, 236)
SIGNATURE = (
    'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', 'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII',
    'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', 'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII',
    'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', 'IIIIIIIIIIII????????IIIIIIIIIIII',
    'IIIIIIIIII??D??????D??IIIIIIIIII', 'IIIIIIIII?D?IIIIIIII?D?IIIIIIIII',
    'IIIIIIII??IIIIIIIIIIII??IIIIIIII', 'IIIIIII??IIIII?II?IIIII??IIIIIII',
    'IIIIII?DIIII?DD??DD?IIIID?IIIIII', 'IIIIII??II??D?D??D?D??II??IIIIII',
    'IIIII?DIII?D?IDDDDI?D?IIID?IIIII', 'IIIII??II?D?II?DD?II?D?II??IIIII',
    'IIIII??I?D?III?DD?III?D?I??IIIII', 'IIIII??I?D?III?DD?III?D?I??IIIII',
    'IIIII??IDDIIIIDDDDIIIIDDI??IIIII', 'IIIII??ID?III?D??D?III?DI??IIIII',
    'IIIII??ID?II?DD??DD?II?DI??IIIII', 'IIIII?DID?II?DDIIDD?II?DID?IIIII',
    'IIIIII??D?I?DD?II?DD?I?D??IIIIII', 'IIIIII?DD???DD?II?DD???DD?IIIIII',
    'IIIIIII?D?II??IIII??II?D?IIIIIII', 'IIIIIIII??IIIIIIIIIIII??IIIIIIII',
    'IIIIIIIII?D?IIIIIIII?D?IIIIIIIII', 'IIIIIIIIII??D??????D??IIIIIIIIII',
    'IIIIIIIIIIII????????IIIIIIIIIIII', 'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII',
    'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', 'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII',
    'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', 'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII',
)


def decode_png(data):
    if not isinstance(data, bytes) or not 45 <= len(data) <= 8 * 1024 * 1024 or data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('ICON_PNG_REJECTED')
    at = 8; chunks = []; header = None; cgbi = False; ended = False
    while at < len(data):
        if at + 12 > len(data): raise ValueError('ICON_CHUNK_REJECTED')
        size = struct.unpack_from('>I', data, at)[0]; kind = data[at+4:at+8]
        if size > 8 * 1024 * 1024 or at + size + 12 > len(data): raise ValueError('ICON_CHUNK_REJECTED')
        payload = data[at+8:at+8+size]
        if zlib.crc32(kind + payload) & 0xffffffff != struct.unpack_from('>I', data, at+8+size)[0]: raise ValueError('ICON_CRC_REJECTED')
        if kind == b'CgBI':
            if header is not None or cgbi: raise ValueError('ICON_CGBI_REJECTED')
            cgbi = True
        elif kind == b'IHDR':
            if header is not None or size != 13: raise ValueError('ICON_HEADER_REJECTED')
            header = struct.unpack('>IIBBBBB', payload)
        elif kind == b'IDAT':
            if header is None: raise ValueError('ICON_CHUNK_ORDER_REJECTED')
            chunks.append(payload)
        elif kind == b'IEND':
            if size or at + 12 != len(data): raise ValueError('ICON_END_REJECTED')
            ended = True; break
        elif kind[0] & 32 == 0: raise ValueError('ICON_CRITICAL_CHUNK_REJECTED')
        at += size + 12
    if not ended or header is None or not chunks: raise ValueError('ICON_CONTENT_REJECTED')
    w, h, depth, colour, compression, filter_method, interlace = header
    if w != h or not 32 <= w <= 1024 or depth != 8 or colour not in (2, 6) or (compression, filter_method, interlace) != (0, 0, 0): raise ValueError('ICON_FORMAT_REJECTED')
    channels = 3 if colour == 2 else 4; stride = w * channels
    inflater = zlib.decompressobj(-15 if cgbi else 15)
    raw = inflater.decompress(b''.join(chunks), (stride + 1) * h + 1)
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail or len(raw) != (stride + 1) * h: raise ValueError('ICON_DEFLATE_REJECTED')
    output = bytearray(); previous = bytearray(stride)
    for y in range(h):
        kind = raw[y*(stride+1)]; row = bytearray(raw[y*(stride+1)+1:(y+1)*(stride+1)])
        if kind > 4: raise ValueError('ICON_FILTER_REJECTED')
        for x in range(stride):
            left = row[x-channels] if x >= channels else 0; up = previous[x]; corner = previous[x-channels] if x >= channels else 0
            if kind == 1: predict = left
            elif kind == 2: predict = up
            elif kind == 3: predict = (left + up) // 2
            elif kind == 4:
                p = left + up - corner; distances = (abs(p-left), abs(p-up), abs(p-corner))
                predict = (left, up, corner)[distances.index(min(distances))]
            else: predict = 0
            row[x] = (row[x] + predict) & 255
        for x in range(0, stride, channels):
            if channels == 4 and row[x+3] != 255: raise ValueError('ICON_ALPHA_REJECTED')
            output.extend((row[x+2], row[x+1], row[x]) if cgbi else row[x:x+3])
        previous = row
    return w, bytes(output)


def circle_visual_proof(data):
    size, pixels = decode_png(data)
    checked = 0; valid = True
    for y, row in enumerate(SIGNATURE):
        for x, label in enumerate(row):
            if label == '?': continue
            at = ((int((y + .5) * size / 32) * size) + int((x + .5) * size / 32)) * 3
            expected = BROWN if label == 'D' else IVORY
            valid &= all(abs(pixels[at+i] - expected[i]) <= 25 for i in range(3)); checked += 1
    return {'size': size, 'pixelSha256': hashlib.sha256(pixels).hexdigest(), 'stableSamples': checked, 'circleVisualMatches': valid and checked == 854}


def signed_icon_proof(info, read, verified, names):
    primary = (info.get('CFBundleIcons') or {}).get('CFBundlePrimaryIcon') or {}
    declared = primary.get('CFBundleIconFiles', info.get('CFBundleIconFiles', []))
    if not isinstance(declared, list) or any(not isinstance(n, str) or '/' in n or '\\' in n for n in declared): declared = []
    candidates = [name for name in names if re.fullmatch(r'AppIcon[0-9]+x[0-9]+(?:@[23]x)?(?:~iphone)?\.png', name)]
    selected = [name for name in candidates if any(name.startswith(base.removesuffix('.png')) for base in declared)]
    proofs = []; valid = bool(selected)
    for name in selected:
        if name not in verified: valid = False; continue
        try:
            data = read(name); proof = circle_visual_proof(data)
            proofs.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), **proof})
            valid &= proof['circleVisualMatches']
        except (ValueError, zlib.error, KeyError, OSError): valid = False
    return {'nativePrimaryIconPNGCount': len(selected), 'nativeIconPNGProofs': proofs,
            'signedNativeCircleIconVisualVerified': bool(valid) and len(proofs) == len(selected),
            'nativeIconAssetCatalogSignedResourceBound': 'Assets.car' in names and 'Assets.car' in verified,
            'nativeStoreIconInputSha256': INPUT_ICON_SHA256, 'originalCircleInputSha256': ORIGINAL_CIRCLE_SHA256,
            'physicalIOSLauncherVerificationPerformed': False}
