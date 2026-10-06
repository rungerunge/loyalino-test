'use strict';
const crypto = require('node:crypto');
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const PARENT_NATIVE_SHA = '018a55e35e81ab9fd085067322987f251d52bca39082b2a27582f6d6efa77bf0';
const PARENT_POLICY_SHA = '0716f5f9852b8519b80b70687d8a505fc6c4f3b0b76dd877dcec7449b9f6e000';
const OLD_A50 = 'a50ff5b4-6c39-41d5-8559-e76dd33cf663';
const OLD_9C = '9c1a13ee-2f36-4f21-a065-7c4af835e0f7';
const BEFORE = "    magic, length, count = struct.unpack_from('>III', code)\n    require(magic == 0xfade0cc0 and length == len(code) and 0 < count <= 32)";
const AFTER = '    code, count = signature_capacity(code)\n    length = len(code)';
const HELPER = String.raw`# BEGIN declared SuperBlob capacity proof.
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

`;
const FAILURE_BEFORE = "    return {'nativeAuditVerified':False,'diagnosticOnly':True,'exceptionType':label,\n            'sourceFrames':frames[-2:]}";
const FAILURE_AFTER = "    result = {'nativeAuditVerified':False,'diagnosticOnly':True,'exceptionType':label,\n              'sourceFrames':frames[-2:]}\n    shape = signature_failure_shape(error)\n    if shape is not None:\n        result['signatureCapacity'] = shape\n    return result";
function once(source, before, after) {
  if (typeof source !== 'string' || source.split(before).length !== 2) throw Error('SIGNATURE_DERIVATION_REFUSED');
  return source.replace(before, after);
}
function native(source) {
  if (sha(source) !== PARENT_NATIVE_SHA) throw Error('PARENT_NATIVE_REFUSED');
  source = once(source, 'def executable(part, info_raw, resources_raw):', HELPER + 'def executable(part, info_raw, resources_raw):');
  source = once(source, BEFORE, AFTER);
  source = once(source, "'require','audit','current_fixes','executable','runtime_config_proof'", "'require','audit','current_fixes','executable','signature_capacity','signature_failure_shape','runtime_config_proof'");
  return once(source, FAILURE_BEFORE, FAILURE_AFTER);
}
function restoreNative(source) {
  source = once(source, HELPER, '');
  source = once(source, AFTER, BEFORE);
  source = once(source, "'require','audit','current_fixes','executable','signature_capacity','signature_failure_shape','runtime_config_proof'", "'require','audit','current_fixes','executable','runtime_config_proof'");
  source = once(source, FAILURE_AFTER, FAILURE_BEFORE);
  if (sha(source) !== PARENT_NATIVE_SHA) throw Error('NATIVE_ANCESTRY_REFUSED');
  return source;
}
function policy(source) {
  if (sha(source) !== PARENT_POLICY_SHA) throw Error('PARENT_POLICY_REFUSED');
  const anchor = "v.operationId==='f8955263-133c-4d9f-92fe-b915f7722c23'||";
  return once(source, anchor, anchor + "v.operationId==='" + OLD_A50 + "'||v.operationId==='" + OLD_9C + "'||");
}
function rootHistory(source) {
  const before = "require('./failed-operation-f895.cjs')";
  if (typeof source !== 'string' || source.split(before).length !== 3) throw Error('ROOT_HISTORY_ANCHORS_REFUSED');
  return source.replaceAll(before, "require('./failed-operation-9c.cjs')");
}
module.exports = {sha, PARENT_NATIVE_SHA, PARENT_POLICY_SHA, OLD_A50, OLD_9C, BEFORE, AFTER, HELPER, FAILURE_BEFORE, FAILURE_AFTER, native, restoreNative, policy, rootHistory};
