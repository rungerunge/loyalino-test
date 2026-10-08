$ErrorActionPreference='Stop'
# SignedCms algorithm from the original native audit, applied to CI17 evidence.
try {
 if($PSVersionTable.PSVersion.ToString() -ne '7.6.5') {throw 'REFUSED'}
 $raw=[Console]::In.ReadToEnd(); if($raw.Length -gt 1500000) {throw 'REFUSED'}; $v=$raw | ConvertFrom-Json -AsHashtable
 if((($v.Keys | Sort-Object) -join ',') -ne 'certificateSerialSha256,cms,codeDirectory,profile,profileUuidSha256,referenceProfile') {throw 'REFUSED'}
 Add-Type -AssemblyName System.Security.Cryptography.Pkcs
 $profileBytes=[Convert]::FromBase64String($v.profile); if($profileBytes.Length -gt 524288 -or $v.profile -cne $v.referenceProfile) {throw 'REFUSED'}
 $p=[Security.Cryptography.Pkcs.SignedCms]::new(); $p.Decode($profileBytes); $p.CheckSignature($true)
 $xml=[Xml.XmlDocument]::new(); $xml.XmlResolver=$null; $xml.LoadXml([Text.Encoding]::UTF8.GetString($p.ContentInfo.Content))
 $uuid=$xml.SelectSingleNode("/plist/dict/key[text()='UUID']/following-sibling::*[1]").InnerText.ToUpperInvariant()
 $hash={param([string]$x) [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($x))).ToLowerInvariant()}
 if((&$hash $uuid) -ne $v.profileUuidSha256) {throw 'REFUSED'}
 $cd=[Convert]::FromBase64String($v.codeDirectory); $cmsBytes=[Convert]::FromBase64String($v.cms); if($cd.Length -gt 1048576 -or $cmsBytes.Length -gt 1048576) {throw 'REFUSED'}
 $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($cd),$true); $cms.Decode($cmsBytes); $cms.CheckSignature($true)
 if($cms.SignerInfos.Count -ne 1) {throw 'REFUSED'}; $leaf=$cms.SignerInfos[0].Certificate
 if((&$hash $leaf.SerialNumber.ToUpperInvariant()) -ne $v.certificateSerialSha256 -or $leaf.Subject -notmatch '(?:^|,\s*)OU\s*=\s*XNPLDX9MHP(?:,|$)' -or $leaf.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {throw 'REFUSED'}
 $members=@($xml.SelectNodes("/plist/dict/key[text()='DeveloperCertificates']/following-sibling::*[1]/data") | Where-Object {[Convert]::ToBase64String([Convert]::FromBase64String($_.InnerText)) -ceq [Convert]::ToBase64String($leaf.RawData)})
 if($members.Count -ne 1) {throw 'REFUSED'}
 [Console]::Out.WriteLine('{"embeddedProfileExact":true,"profileCmsVerified":true,"executableCmsVerified":true,"expectedSignerVerified":true}')
} catch { [Console]::Out.WriteLine('{"cmsValidation":false}'); exit 1 }
