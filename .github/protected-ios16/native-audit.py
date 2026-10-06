"""CI16 independent byte audit. Explicit private IPA only; no default I/O.
Uses the original resource-hash algorithm, never its EAS15 receipt guard.
CMS blobs remain private and are verified separately by SignedCms7.6.5.
"""
import hashlib, json, math, plistlib, re, struct, sys, zipfile
from pathlib import Path
from artifact_guard import verify_resource_hashes, otp_marker_evidence, wallet_marker_evidence, require_cart_consent_evidence
from feature_guard import camera_locale_proof, financial_info_proof, benefit_marker_proof
from notifications_guard import inbox_marker_proof, inbox_privacy_proof
from icon_guard import signed_icon_proof
from lucky_days_guard import lucky_days_marker_proof, signed_sdk_proof
from brightness_guard import MARKERS as BRIGHTNESS_MARKERS
TEAM = 'XNPLDX9MHP'
BUNDLE = 'dk.nevermonday.app'
API = b'https://backend-production-d356.up.railway.app/api/mobile/v1'
CART_MARKERS=(b'Cart identity changed',b'nm.cartId',b'isInternetReachable',b'cancelQueries',b'refetchQueries')
QUERY_MARKERS=(b'subscribeQueryNetwork',b'refetchOnReconnect',b'networkMode',b'setEventListener',b'isConnected',b'isInternetReachable')
# BEGIN signed runtime configuration proof (source-derived Expo Constants loader).
RUNTIME_CONFIG = 'EXConstants.bundle/app.config'
HERMES_MAGIC = bytes.fromhex('c61fbc03c103191f')
RUNTIME_SDK = '57.0.0'
RUNTIME_PROJECT = 'adf6c486-4d81-4e19-b6b7-25e5b4ca1064'

def _unique_runtime_object(pairs):
    value = {}
    for key, item in pairs:
        require(isinstance(key, str) and key not in value)
        value[key] = item
    return value

def _invalid_runtime_constant(value):
    require(False)

def runtime_config_proof(configs, verified, prefix=''):
    require(isinstance(configs, list) and len(configs) == 1)
    name, raw = configs[0]
    require(name == prefix + RUNTIME_CONFIG and RUNTIME_CONFIG in verified)
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_runtime_object,
                       parse_constant=_invalid_runtime_constant)
    require(isinstance(value, dict))
    require(value.get('sdkVersion') == RUNTIME_SDK)
    extra = value.get('extra')
    require(isinstance(extra, dict))
    require(extra.get('apiBase') == API.decode('ascii'))
    eas = extra.get('eas')
    require(isinstance(eas, dict) and eas.get('projectId') == RUNTIME_PROJECT)
    return True

def bundle_runtime_proof(bundle, configs, verified, prefix=''):
    require(isinstance(bundle, bytes) and bundle[:8] == HERMES_MAGIC)
    require(b'https://api.nevermonday.dk/api/mobile/v1' not in bundle)
    return runtime_config_proof(configs, verified, prefix)
def runtime_config_preflight(names, prefix, information):
    candidates = [name for name in names if name.endswith('app.config')]
    require(len(candidates) == 1)
    name = candidates[0]
    require(name == prefix + RUNTIME_CONFIG)
    size = information(name).file_size
    require(isinstance(size, int) and not isinstance(size, bool) and 0 < size <= 65536)
    return name, size

def archive_runtime_proof(bundle, names, verified, prefix, information, read):
    name, size = runtime_config_preflight(names, prefix, information)
    require(RUNTIME_CONFIG in verified)
    raw = read(name)
    require(isinstance(raw, bytes) and len(raw) == size)
    return bundle_runtime_proof(bundle, [(name, raw)], verified, prefix)

# END signed runtime configuration proof.

def current_fixes(bundle,verified):
    require('main.jsbundle' in verified and all(m in bundle for m in CART_MARKERS) and all(m in bundle for m in QUERY_MARKERS))
    manifest_raw=Path(__file__).with_name('public-source-manifest.json').read_bytes()
    require(hashlib.sha256(manifest_raw).hexdigest()=='d7e44f0fc256fb9fa8521425d2d98baf57a1ccc99edd944066946f13816df6e1')
    manifest=json.loads(manifest_raw); require(manifest['nativeSource']=='6aa3fc0fed9ccdd929533632ed1edef2e1f8cde5' and manifest['backendSource']=='a59e987d45d59ae6e6cdc53620c1640495cd4626' and len(manifest['files'])==249)
    source={r['path']:r['sha256'] for r in manifest['files']}
    return {'cartRecoveryCompiledMarkersVerified':True,'queryReconnectCompiledMarkersVerified':True,'nativeSource':manifest['nativeSource'],'backendSource':manifest['backendSource'],'sourceManifestSha256':hashlib.sha256(manifest_raw).hexdigest(),'cartSourceSha256':source['src/lib/cart.tsx'],'queryNetworkSourceSha256':source['src/lib/query-network.ts'],'queriesSourceSha256':source['src/lib/queries.ts'],'nativeRecoveryBehaviorVerified':False}
def require(v):
    if not v: raise ValueError('CI16_NATIVE_REFUSED')
# BEGIN declared SuperBlob capacity proof.
def signature_capacity(code):
    readable = isinstance(code, bytes) and len(code) >= 12
    extent = len(code) if isinstance(code, bytes) else 0
    magic, length, count = struct.unpack_from('>III', code) if readable else (0, 0, 0)
    within = readable and 12 <= length <= extent
    allowed = readable and 0 < count <= 32
    index_fits = within and allowed and 12 + count * 8 <= length
    remaining_zero = within and not any(code[length:])
    shape = {
        'headerReadable': readable,
        'magicMatches': readable and magic == 0xfade0cc0,
        'declaredWithinCapacity': within,
        'declaredEqualsCapacity': readable and length == extent,
        'countAllowed': allowed,
        'indexFitsDeclared': index_fits,
        'remainingCapacityZero': remaining_zero,
        'reservedCapacityBytes': extent,
        'declaredSuperBlobBytes': length,
        'superBlobCount': count,
        'remainingCapacityBytes': extent - length if within else 0,
    }
    if not (shape['magicMatches'] and index_fits and remaining_zero):
        error = ValueError('CI16_NATIVE_REFUSED')
        error.signature_capacity_shape = shape
        raise error
    return code[:length], count

def signature_failure_shape(error):
    # Only the explicitly attached, closed scalar record is eligible for output.
    # Never inspect exception text, traceback locals or any private signature bytes.
    if type(error) is not ValueError:
        return None
    value = getattr(error, 'signature_capacity_shape', None)
    booleans = ('headerReadable', 'magicMatches', 'declaredWithinCapacity',
                'declaredEqualsCapacity', 'countAllowed', 'indexFitsDeclared',
                'remainingCapacityZero')
    integers = ('reservedCapacityBytes', 'declaredSuperBlobBytes',
                'superBlobCount', 'remainingCapacityBytes')
    if (not isinstance(value, dict) or set(value) != set(booleans + integers)
            or any(type(value[key]) is not bool for key in booleans)
            or any(type(value[key]) is not int or not 0 <= value[key] <= 0xffffffff
                   for key in integers)):
        return None
    return {key: value[key] for key in booleans + integers}
# END declared SuperBlob capacity proof.

def executable(part, info_raw, resources_raw):
    require(part[:4] == bytes.fromhex('cffaedfe') and len(part) > 32)
    count, cmds = struct.unpack_from('<II', part, 16)
    require(0 < count < 10000 and cmds <= len(part)-32)
    at, signature = 32, None
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', part, at)
        require(length >= 8 and at+length <= 32+cmds)
        if cmd == 0x1d:
            require(signature is None and length == 16)
            offset, size = struct.unpack_from('<II', part, at+8)
            require(offset >= 32+cmds and offset+size == len(part))
            signature = (offset, part[offset:offset+size])
        at += length
    require(at == 32+cmds and signature is not None)
    limit, code = signature
    code, count = signature_capacity(code)
    length = len(code)
    blobs, spans = {}, []
    for i in range(count):
        slot, offset = struct.unpack_from('>II', code, 12+i*8)
        require(slot not in blobs and offset >= 12+count*8 and offset+8 <= length)
        magic, size = struct.unpack_from('>II', code, offset)
        require(size >= 8 and offset+size <= length)
        spans.append((offset, offset+size)); blobs[slot] = code[offset:offset+size]
    spans.sort(); require(all(a[1] <= b[0] for a,b in zip(spans,spans[1:])))
    require(all(s in blobs for s in [0,5,7,65536]))
    ent = plistlib.loads(blobs[5][8:])
    require(ent.get('com.apple.developer.team-identifier') == TEAM and ent.get('application-identifier') == TEAM+'.'+BUNDLE and ent.get('get-task-allow') is False and ent.get('aps-environment') == 'production' and ent.get('com.apple.developer.associated-domains') == ['applinks:nevermonday.dk'])
    directories = []
    for slot, cd in blobs.items():
        if slot != 0 and not 4096 <= slot < 4102: continue
        require(len(cd) >= 52 and struct.unpack_from('>I', cd)[0] == 0xfade0c02)
        version, flags, hashoff, identoff, nspec, ncode, coded_limit = struct.unpack_from('>7I', cd, 8)
        hsize, htype, platform, power = struct.unpack_from('>4B', cd,36)
        require(htype in [1,2,3,4] and hsize == {1:20,2:32,3:20,4:48}[htype] and power <= 20 and nspec >= 7)
        if version >= 0x20300:
            large = struct.unpack_from('>Q', cd,56)[0]
            if large: coded_limit = large
        require(coded_limit == limit and hashoff-nspec*hsize >= 0 and hashoff+ncode*hsize <= len(cd) and version >= 0x20200)
        teamoff = struct.unpack_from('>I',cd,48)[0]
        require(0 < teamoff < hashoff and cd[teamoff:].split(b'\0',1)[0] == TEAM.encode())
        alg = {1:'sha1',2:'sha256',3:'sha256',4:'sha384'}[htype]
        digest = lambda b: hashlib.new(alg,b).digest()[:hsize]
        for n,b in [(1,info_raw),(3,resources_raw),(5,blobs[5]),(7,blobs[7])]:
            require(cd[hashoff-n*hsize:hashoff-(n-1)*hsize] == digest(b))
        page = 1 << power if power else limit
        require(ncode == math.ceil(limit/page) and ncode > 0)
        require(all(cd[hashoff+i*hsize:hashoff+(i+1)*hsize] == digest(part[i*page:min((i+1)*page,limit)]) for i in range(ncode)))
        directories.append(cd)
    require(len(directories)>0 and struct.unpack_from('>I',blobs[65536])[0] == 0xfade0b01)
    import base64
    return {'codeDirectory':base64.b64encode(blobs[0]).decode(),'cms':base64.b64encode(blobs[65536][8:]).decode(),'codeDirectories':len(directories)}
def audit(file):
    raw = Path(file).read_bytes(); require(1000000 <= len(raw) <= 200*1024*1024 and raw[:4] == b'PK\x03\x04')
    with zipfile.ZipFile(file) as z:
        names=z.namelist(); require(len(names)==len(set(names)) and len(names)<50000)
        require(all(not n.startswith('/') and '\\' not in n and '..' not in n.split('/') for n in names))
        require(sum(i.file_size for i in z.infolist()) <= 1024*1024*1024)
        mains=[n for n in names if re.fullmatch(r'Payload/[^/]+\.app/Info\.plist',n)]; require(len(mains)==1)
        app=mains[0][:-10]; runtime_config_preflight(names, app, z.getinfo); info_raw=z.read(mains[0]); info=plistlib.loads(info_raw)
        require(info.get('CFBundleIdentifier')==BUNDLE and info.get('CFBundleVersion')=='16' and info.get('CFBundleShortVersionString')=='1.0.0' and info.get('UIDeviceFamily')==[1] and info.get('ITSAppUsesNonExemptEncryption') is False)
        require(info.get('CFBundleLocalizations') and sorted(info['CFBundleLocalizations'])==['da','en'] and info.get('CFBundleDevelopmentRegion')=='da')
        require('NSMicrophoneUsageDescription' not in info and 'NSUserTrackingUsageDescription' not in info)
        executable_name=info.get('CFBundleExecutable'); require(isinstance(executable_name,str) and '/' not in executable_name and '\\' not in executable_name)
        resources_raw=z.read(app+'_CodeSignature/CodeResources'); resources=plistlib.loads(resources_raw)
        verified,mismatch,nested=verify_resource_hashes(resources.get('files2',{}),app,z.read,names)
        declared={n for n,e in resources.get('files2',{}).items() if isinstance(e,dict) and ('hash' in e or 'hash2' in e) and app+n in names}
        require(verified==declared and len(verified)>=142 and mismatch==0 and nested==0 and 'main.jsbundle' in verified)
        require('PrivacyInfo.xcprivacy' in verified)
        privacy=plistlib.loads(z.read(app+'PrivacyInfo.xcprivacy'))
        require(privacy.get('NSPrivacyTracking') is False and privacy.get('NSPrivacyTrackingDomains')==[])
        declarations=privacy.get('NSPrivacyCollectedDataTypes'); require(isinstance(declarations,list) and len(declarations)==11)
        require(all(d.get('NSPrivacyCollectedDataTypeLinked') is True and d.get('NSPrivacyCollectedDataTypeTracking') is False for d in declarations))
        require({d.get('NSPrivacyCollectedDataType') for d in declarations}=={'NSPrivacyCollectedDataTypeEmailAddress','NSPrivacyCollectedDataTypeName','NSPrivacyCollectedDataTypePhoneNumber','NSPrivacyCollectedDataTypePhysicalAddress','NSPrivacyCollectedDataTypePaymentInfo','NSPrivacyCollectedDataTypeOtherFinancialInfo','NSPrivacyCollectedDataTypePurchaseHistory','NSPrivacyCollectedDataTypeUserID','NSPrivacyCollectedDataTypeDeviceID','NSPrivacyCollectedDataTypeProductInteraction','NSPrivacyCollectedDataTypeOtherDataTypes'})
        bundle=z.read(app+'main.jsbundle'); archive_runtime_proof(bundle, names, verified, app, z.getinfo, z.read)
        require(otp_marker_evidence(bundle)==2 and wallet_marker_evidence(bundle)==6); require_cart_consent_evidence(bundle,verified)
        fixes=current_fixes(bundle,verified)
        for marker in [b'wallet-pass-screen',b'getSessionRevision',b'home-member-summary']:
            require(marker in bundle)
        features={**camera_locale_proof(info,lambda n:z.read(app+n),verified),**benefit_marker_proof(bundle,verified),**inbox_marker_proof(bundle,verified),**inbox_privacy_proof(privacy),**lucky_days_marker_proof(bundle,verified),**signed_sdk_proof([(n,z.read(app+n)) for n in verified if n.endswith('app.config')],verified),**signed_icon_proof(info,lambda n:z.read(app+n),verified,[n[len(app):] for n in names if n.startswith(app)])}
        require(all(value for key,value in features.items() if isinstance(value,bool) and key!='physicalIOSLauncherVerificationPerformed'))
        require(financial_info_proof(privacy) and all(marker in bundle for marker in BRIGHTNESS_MARKERS))
        signature=executable(z.read(app+executable_name),info_raw,resources_raw)
        import base64
        return {'kind':'ROOT_CI16_INDEPENDENT_BYTE_AUDIT','ipaBytes':len(raw),'ipaSha256':hashlib.sha256(raw).hexdigest(),'version':16,'bundle':BUNDLE,'team':TEAM,'resourceCount':len(verified),'independentSignedResourcesVerified':True,'hermesSourceAssociationVerified':True,'privacyManifestVerified':True,'compiledFeaturesVerified':True,'currentFixes':fixes,'cmsEvidence':{'profile':base64.b64encode(z.read(app+'embedded.mobileprovision')).decode(),**signature},'nativeUiVerified':False,'currentAppleRevocationVerified':False,'easFinishedVerified':False}
def failure_projection(error):
    # Diagnostic only. Never stringify exceptions, values, paths or IPA material.
    classes=((ValueError,'ValueError'),(AssertionError,'AssertionError'),(KeyError,'KeyError'),(TypeError,'TypeError'),
             (AttributeError,'AttributeError'),(IndexError,'IndexError'),
             (OverflowError,'OverflowError'),(FileNotFoundError,'FileNotFoundError'),
             (PermissionError,'PermissionError'),(OSError,'OSError'),
             (UnicodeDecodeError,'UnicodeDecodeError'),(json.JSONDecodeError,'JSONDecodeError'),
             (zipfile.BadZipFile,'BadZipFile'),(plistlib.InvalidFileException,'InvalidFileException'),
             (struct.error,'StructError'))
    label=next((label for kind,label in classes if type(error) is kind),'OtherSuppressed')
    functions={
        'native-audit.py':('require','audit','current_fixes','executable','signature_capacity','signature_failure_shape','runtime_config_proof','bundle_runtime_proof','archive_runtime_proof','runtime_config_preflight','_unique_runtime_object','_invalid_runtime_constant','<module>'),
        'artifact_guard.py':('verify_resource_hashes','otp_marker_evidence','wallet_marker_evidence','require_cart_consent_evidence'),
        'feature_guard.py':('camera_locale_proof','financial_info_proof','benefit_marker_proof'),
        'notifications_guard.py':('inbox_marker_proof','inbox_privacy_proof'),
        'icon_guard.py':('decode_png','circle_visual_proof','signed_icon_proof'),
        'lucky_days_guard.py':('lucky_days_marker_proof','signed_sdk_proof'),
        'brightness_guard.py':('brightness_marker_proof',)}
    sources={str(Path(__file__).with_name(name)):(name,names) for name,names in functions.items()}
    frames=[]
    trace=error.__traceback__
    while trace is not None:
        code=trace.tb_frame.f_code
        source=sources.get(code.co_filename)
        if source is not None and code.co_name in source[1] and isinstance(trace.tb_lineno,int) and 0<trace.tb_lineno<=10000:
            frames.append({'file':source[0],'line':trace.tb_lineno})
        trace=trace.tb_next
    result = {'nativeAuditVerified':False,'diagnosticOnly':True,'exceptionType':label,
              'sourceFrames':frames[-2:]}
    shape = signature_failure_shape(error)
    if shape is not None:
        result['signatureCapacity'] = shape
    return result
if __name__=='__main__':
    try:
        require(len(sys.argv)==2); print(json.dumps(audit(sys.argv[1]),separators=(',',':')))
    except Exception as error:
        print(json.dumps(failure_projection(error),separators=(',',':'))); sys.exit(1)
