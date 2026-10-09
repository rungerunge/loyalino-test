'use strict';
const P=require('./policy.cjs'),Q=require('./export-query.cjs'),E=require('./envelope.cjs'),T=require('./transport.cjs');
// Protected root adapter only. Dependencies/auth/material validation are supplied
// by the separately source-held root adapter; no SDK import or network on default.
async function exportSigner(approval,ports){
 if(!ports||!['now','check','auth','query','validateMaterial','sealPackage','reserve','record'].every(k=>typeof ports[k]==='function')||!ports.metadataPolicy)P.fail();
 const now=ports.now,check=()=>{ports.check();P.approval(approval,now());},old=ports.metadataPolicy;
 check();ports.reserve(approval.operationId);let credential=null,material=null;
 try{
  credential=ports.auth();const deadline=now()+T.DEADLINE_MS;
  const currentVersion=Q.version(await ports.query('VERSION',null,credential,deadline));check();
  const first=await ports.query('IDENTITY',null,credential,deadline);check();
  const selected=old.discover(first,approval);
  const metadata=await ports.query('METADATA',selected.identifierId,credential,deadline);check();
  const assessed=old.assess(metadata,approval,selected,now());
  // Secret material is fetched only after exact current owner/project/team/
  // bundle/stored-validity/reference checks pass. No first-row SDK default.
  const raw=await ports.query('MATERIAL',selected.identifierId,credential,deadline);check();
  const resolved=Q.material(raw,approval,selected,now(),old);material=resolved.material;
  if(JSON.stringify(P.canonical(resolved.metadata))!==JSON.stringify(P.canonical(metadata)))P.fail();
  const stable=['ownerAccountSha256','referenceSigningProofSha256','certificateSerialSha256','profileUuidSha256','certificateIdSha256','profileIdSha256','buildCredentialIdSha256','certificateNotBefore','certificateNotAfter','profileExpiration','storedProfileStatus'];
  if(stable.some(k=>assessed[k]!==resolved.assessment[k]))P.fail();
  // Must parse actual P12 key/certificate + signed CMS/entitlements with the
  // pinned independent root native algorithms. Metadata alone never suffices.
  const validation=await ports.validateMaterial(material,approval);check();
  if(!P.exact(validation,['certificateKeyPairVerified','profileCmsVerified','profileEntitlementsVerified','certificateSerialSha256','profileUuidSha256','team','bundle'])||validation.certificateKeyPairVerified!==true||validation.profileCmsVerified!==true||validation.profileEntitlementsVerified!==true||validation.certificateSerialSha256!==approval.certificateSerialSha256||validation.profileUuidSha256!==approval.profileUuidSha256||validation.team!==P.TEAM||validation.bundle!==P.BUNDLE)P.fail();
  const final=ports.auth();try{if(final.type!==credential.type||final.value!==credential.value)P.fail();}finally{final.value=null;}
  check();const result=await ports.sealPackage(material,approval,validation);check();
  if(!P.exact(result,['operationId','cipherSha256','cipherBytes','sourceManifestSha256','plaintextSavedPublic','signerSavedPublic','keySavedPublic'])||result.operationId!==approval.operationId||!P.SHA.test(result.cipherSha256)||!Number.isSafeInteger(result.cipherBytes)||result.cipherBytes<1||result.cipherBytes>=2147483648||result.sourceManifestSha256!==approval.publicSourceManifestSha256||['plaintextSavedPublic','signerSavedPublic','keySavedPublic'].some(k=>result[k]!==false))P.fail();
  const summary={kind:'ROOT_PROTECTED_IOS18_SIGNER_EXPORT_SEALED',operationId:approval.operationId,finishedAt:new Date(now()).toISOString(),cipherSha256:result.cipherSha256,cipherBytes:result.cipherBytes,sourceManifestSha256:result.sourceManifestSha256,existingSignerOnly:true,credentialQueryCount:3,versionQueryCount:1,totalQueryCount:4,...currentVersion,credentialMutations:0,appleLoginInvoked:false,publicSecretMaterial:false,actualCiJobCreated:false,productionSigningReady:false,noAutomaticRetry:true};ports.record(summary);return summary;
 }catch{throw Error('PROTECTED_SIGNER_EXPORT_REFUSED');}
 finally{if(credential)credential.value=null;if(material){material.p12.fill(0);material.cms.fill(0);material.password=null;}}
}
function main(args=[]){if(args.length===0||args.length===1&&args[0]==='--prepare')return{preparedOnly:true,actualInputReads:0,credentialQueries:0,credentialExports:0,jobsDispatched:0};P.fail();}
module.exports={exportSigner,main};
if(require.main===module)process.stdout.write(JSON.stringify(main(process.argv.slice(2)))+'\n');
