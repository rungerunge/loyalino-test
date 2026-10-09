$ErrorActionPreference='Stop'
# Explicit synthetic test only. No certificate store, files or actual identities.
if($args.Count -ne 1 -or $args[0] -ne '--synthetic') {exit 1}
$rsa=[Security.Cryptography.RSA]::Create(2048)
$request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=synthetic-only,OU=XNPLDX9MHP,O=fixture.invalid',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
$cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1),[DateTimeOffset]::UtcNow.AddDays(2))
$uuid='11111111-2222-3333-4444-555555555555'; $der=[Convert]::ToBase64String($cert.RawData)
$xml='<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>UUID</key><string>'+ $uuid +'</string><key>TeamIdentifier</key><array><string>XNPLDX9MHP</string></array><key>DeveloperCertificates</key><array><data>'+ $der +'</data></array><key>ExpirationDate</key><date>'+[DateTime]::UtcNow.AddDays(1).ToString('yyyy-MM-ddTHH:mm:ssZ')+'</date><key>Entitlements</key><dict><key>com.apple.developer.team-identifier</key><string>XNPLDX9MHP</string><key>application-identifier</key><string>XNPLDX9MHP.dk.nevermonday.app</string><key>get-task-allow</key><false/><key>aps-environment</key><string>production</string><key>com.apple.developer.associated-domains</key><array><string>applinks:nevermonday.dk</string></array></dict></dict></plist>'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([Text.Encoding]::UTF8.GetBytes($xml)))
$signer=[Security.Cryptography.Pkcs.CmsSigner]::new($cert);$cms.ComputeSignature($signer,$true)
$hash={param([string]$x) [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($x))).ToLowerInvariant()}
$password='synthetic-only';$p12=$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12,$password)
$result=[ordered]@{p12=[Convert]::ToBase64String($p12);cms=[Convert]::ToBase64String($cms.Encode());password=$password;certificateSerialSha256=(&$hash $cert.SerialNumber.ToUpperInvariant());profileUuidSha256=(&$hash $uuid);team='XNPLDX9MHP';bundle='dk.nevermonday.app'}
[Console]::Out.WriteLine(($result | ConvertTo-Json -Compress));$cert.Dispose();$rsa.Dispose();[Array]::Clear($p12)
