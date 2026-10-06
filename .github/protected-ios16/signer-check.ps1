$ErrorActionPreference='Stop'
# Protected stdin only. No password/credential argument, file or error output.
function Hash-Text([string]$v) { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($v))).ToLowerInvariant() }
function Plist-Value($node,$depth=0) {
 if($depth -gt 24) { throw 'REFUSED' }
 switch($node.Name) {
  'dict' { $d=@{}; $a=@($node.ChildNodes | Where-Object {$_.NodeType -eq 'Element'}); if($a.Count % 2) {throw 'REFUSED'}; for($i=0;$i -lt $a.Count;$i+=2) { if($a[$i].Name -ne 'key' -or $d.ContainsKey($a[$i].InnerText)) {throw 'REFUSED'}; $d[$a[$i].InnerText]=Plist-Value $a[$i+1] ($depth+1) }; return $d }
  'array' { return ,@($node.ChildNodes | Where-Object {$_.NodeType -eq 'Element'} | ForEach-Object {Plist-Value $_ ($depth+1)}) }
  'string' {return $node.InnerText}; 'data' {return ,([Convert]::FromBase64String($node.InnerText))}; 'date' {return [DateTimeOffset]::Parse($node.InnerText)}
  'integer' {return [long]$node.InnerText}; 'true' {return $true}; 'false' {return $false}; default {throw 'REFUSED'}
 }
}
try {
 if($PSVersionTable.PSVersion.ToString() -ne '7.6.5') {throw 'REFUSED'}
 $raw=[Console]::In.ReadToEnd(); if($raw.Length -gt 1500000) {throw 'REFUSED'}; $v=$raw | ConvertFrom-Json -AsHashtable
 if((($v.Keys | Sort-Object) -join ',') -ne 'bundle,certificateSerialSha256,cms,p12,password,profileUuidSha256,team') {throw 'REFUSED'}
 if($v.team -ne 'XNPLDX9MHP' -or $v.bundle -ne 'dk.nevermonday.app') {throw 'REFUSED'}
 $p12=[Convert]::FromBase64String($v.p12); $profileBytes=[Convert]::FromBase64String($v.cms)
 if($p12.Length -lt 1 -or $p12.Length -gt 524288 -or $profileBytes.Length -lt 1 -or $profileBytes.Length -gt 524288) {throw 'REFUSED'}
 $certs=[Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
 $certs.Import($p12,[string]$v.password,[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
 $leaves=@($certs | Where-Object {$_.HasPrivateKey}); if($leaves.Count -ne 1) {throw 'REFUSED'}; $leaf=$leaves[0]
 if((Hash-Text $leaf.SerialNumber.ToUpperInvariant()) -ne $v.certificateSerialSha256 -or $leaf.Subject -notmatch '(?:^|,\s*)OU\s*=\s*XNPLDX9MHP(?:,|$)' -or $leaf.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $leaf.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {throw 'REFUSED'}
 $challenge=[Security.Cryptography.RandomNumberGenerator]::GetBytes(32); $priv=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($leaf); $pub=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($leaf)
 if($null -eq $priv -or $null -eq $pub) {throw 'REFUSED'}
 $sig=$priv.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 if(-not $pub.VerifyData($challenge,$sig,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) {throw 'REFUSED'}
 Add-Type -AssemblyName System.Security.Cryptography.Pkcs
 $cms=[Security.Cryptography.Pkcs.SignedCms]::new(); $cms.Decode($profileBytes); $cms.CheckSignature($true)
 $xml=[Xml.XmlDocument]::new(); $xml.XmlResolver=$null; $xml.LoadXml([Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content)); $profile=Plist-Value $xml.plist.dict
 $ent=$profile.Entitlements; $member=@($profile.DeveloperCertificates | Where-Object {[Convert]::ToBase64String([byte[]]$_) -ceq [Convert]::ToBase64String($leaf.RawData)})
 if($member.Count -ne 1 -or (Hash-Text $profile.UUID.ToUpperInvariant()) -ne $v.profileUuidSha256 -or @($profile.TeamIdentifier).Count -ne 1 -or $profile.TeamIdentifier[0] -ne $v.team -or $profile.ExpirationDate -le [DateTimeOffset]::UtcNow -or $profile.ContainsKey('ProvisionedDevices') -or $profile.ProvisionsAllDevices -eq $true -or $ent.'com.apple.developer.team-identifier' -ne $v.team -or $ent.'application-identifier' -ne ($v.team+'.'+$v.bundle) -or $ent.'get-task-allow' -cne $false -or $ent.'aps-environment' -ne 'production' -or (@($ent.'com.apple.developer.associated-domains') -notcontains 'applinks:nevermonday.dk' -and @($ent.'com.apple.developer.associated-domains') -notcontains '*')) {throw 'REFUSED'}
 $result=[ordered]@{certificateKeyPairVerified=$true;profileCmsVerified=$true;profileEntitlementsVerified=$true;certificateSerialSha256=$v.certificateSerialSha256;profileUuidSha256=$v.profileUuidSha256;team=$v.team;bundle=$v.bundle}
 [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
} catch { [Console]::Out.WriteLine('{"protectedSignerValidation":false}'); exit 1 }
finally { if($priv) {$priv.Dispose()}; if($pub) {$pub.Dispose()}; if($certs) {foreach($c in $certs) {$c.Dispose()}}; if($p12) {[Array]::Clear($p12)}; $raw=$null; $v=$null }
