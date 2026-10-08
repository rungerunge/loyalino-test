'use strict';
const P=require('./policy.cjs');
const VERSION=`query LatestAppVersion($appId:String!,$platform:AppPlatform!,$applicationIdentifier:String!){app{byId(appId:$appId){id latestAppVersionByPlatformAndApplicationIdentifier(platform:$platform,applicationIdentifier:$applicationIdentifier){id storeVersion buildVersion}}}}`;
// Exact EAS24.8 schema fields used by the official existing-credential query.
// This is a read query, never the SDK credential setup/create/assign action.
const IDENTITY=`query IOS17ExistingSignerIdentity($appId:String!){app{byId(appId:$appId){id ownerAccount{id name} iosAppCredentials{id appleTeam{id appleTeamIdentifier} appleAppIdentifier{id bundleIdentifier}}}}}`;
const METADATA=`query IOS17ExistingSignerMetadata($appId:String!,$appleAppIdentifierId:String!){app{byId(appId:$appId){id ownerAccount{id name} iosAppCredentials(filter:{appleAppIdentifierId:$appleAppIdentifierId}){id appleTeam{id appleTeamIdentifier} appleAppIdentifier{id bundleIdentifier} iosAppBuildCredentialsList(filter:{iosDistributionType:APP_STORE}){id iosDistributionType distributionCertificate{id serialNumber validityNotBefore validityNotAfter updatedAt appleTeam{id appleTeamIdentifier} account{id name}} provisioningProfile{id appleUUID expiration status updatedAt appleTeam{id appleTeamIdentifier} account{id name} appleAppIdentifier{id bundleIdentifier}}}}}}}`;
const MATERIAL=METADATA.replace('IOS17ExistingSignerMetadata','IOS17ExistingSignerMaterial').replace('distributionCertificate{id serialNumber','distributionCertificate{id certificateP12 certificatePassword serialNumber').replace('provisioningProfile{id appleUUID','provisioningProfile{id provisioningProfile appleUUID');
function request(kind,identifier){if(!['VERSION','IDENTITY','METADATA','MATERIAL'].includes(kind)||['VERSION','IDENTITY'].includes(kind)&&identifier!==null||!['VERSION','IDENTITY'].includes(kind)&&(typeof identifier!=='string'||!/^[A-Za-z0-9_-]{1,100}$/.test(identifier)))P.fail();if(kind==='VERSION')return{query:VERSION,variables:{appId:P.PROJECT,platform:'IOS',applicationIdentifier:P.BUNDLE},operationName:'LatestAppVersion'};return {query:kind==='IDENTITY'?IDENTITY:kind==='METADATA'?METADATA:MATERIAL,variables:kind==='IDENTITY'?{appId:P.PROJECT}:{appId:P.PROJECT,appleAppIdentifierId:identifier},operationName:'IOS17ExistingSigner'+(kind==='IDENTITY'?'Identity':kind==='METADATA'?'Metadata':'Material')};}
function version(data){if(!P.exact(data,['app'])||!P.exact(data.app,['byId'])||!P.exact(data.app.byId,['id','latestAppVersionByPlatformAndApplicationIdentifier'])||data.app.byId.id!==P.PROJECT)P.fail();const v=data.app.byId.latestAppVersionByPlatformAndApplicationIdentifier;if(!P.exact(v,['id','storeVersion','buildVersion'])||typeof v.id!=='string'||!/^[A-Za-z0-9_-]{1,100}$/.test(v.id)||v.storeVersion!=='1.0.0'||v.buildVersion!=='15')P.fail();return{remoteVersion:15,storeVersion:'1.0.0',remoteVersionIdSha256:P.sha(v.id)};}
function material(data,approval,selected,at,oldPolicy){
 if(!P.exact(data,['app'])||!P.exact(data.app,['byId'])||!P.exact(data.app.byId,['id','ownerAccount','iosAppCredentials'])||!Array.isArray(data.app.byId.iosAppCredentials)||data.app.byId.iosAppCredentials.length!==1)P.fail();
 const row=data.app.byId.iosAppCredentials[0];if(!P.exact(row,['id','appleTeam','appleAppIdentifier','iosAppBuildCredentialsList'])||!Array.isArray(row.iosAppBuildCredentialsList)||row.iosAppBuildCredentialsList.length!==1)P.fail();
 const build=row.iosAppBuildCredentialsList[0];if(!P.exact(build,['id','iosDistributionType','distributionCertificate','provisioningProfile']))P.fail();
 const cert=build.distributionCertificate,profile=build.provisioningProfile;
 const certKeys=['id','certificateP12','certificatePassword','serialNumber','validityNotBefore','validityNotAfter','updatedAt','appleTeam','account'],profileKeys=['id','provisioningProfile','appleUUID','expiration','status','updatedAt','appleTeam','account','appleAppIdentifier'];
 if(!P.exact(cert,certKeys)||!P.exact(profile,profileKeys)||typeof cert.certificatePassword!=='string'||cert.certificatePassword.length>1024)P.fail();
 const decode=s=>{if(typeof s!=='string'||s.length<4||s.length>1048576||!/^[A-Za-z0-9+/]+={0,2}$/.test(s))P.fail();const b=Buffer.from(s,'base64');if(b.length<1||b.length>524288||b.toString('base64')!==s)P.fail();return b;};
 let p12,cms;try{p12=decode(cert.certificateP12);cms=decode(profile.provisioningProfile);
 const cleanCert=Object.fromEntries(certKeys.filter(k=>!['certificateP12','certificatePassword'].includes(k)).map(k=>[k,cert[k]])),cleanProfile=Object.fromEntries(profileKeys.filter(k=>k!=='provisioningProfile').map(k=>[k,profile[k]]));
 const metadata={app:{byId:{...data.app.byId,iosAppCredentials:[{...row,iosAppBuildCredentialsList:[{...build,distributionCertificate:cleanCert,provisioningProfile:cleanProfile}]}]}}};
 const assessment=oldPolicy.assess(metadata,approval,selected,at);
 return {metadata,assessment,material:{p12,cms,password:cert.certificatePassword}};
 }catch{p12?.fill(0);cms?.fill(0);P.fail();}
}
module.exports={VERSION,IDENTITY,METADATA,MATERIAL,request,version,material};
