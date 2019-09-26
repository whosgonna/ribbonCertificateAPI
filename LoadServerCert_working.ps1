param(
    [Parameter(Mandatory=$true)] $ip,
    [Parameter(Mandatory=$true)] $user,
    [Parameter(Mandatory=$true)] $pass,
    [Parameter(Mandatory=$true)] $P12File,   ## Filename of the certificate
    [Parameter(Mandatory=$true)] $P12Pass    ## The passphrase for the certificate.
)


 ## Skip certificate validation.  This part is lengthly, but necessary since there is no
 ## publicly trusted certificate installed on the SBC.
 [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCall./loback').Type)
 {
 $certCallback = @"
     using System;
     using System.Net;
     using System.Net.Security;
     using System.Security.Cryptography.X509Certificates;
     public class ServerCertificateValidationCallback
     {
         public static void Ignore()
         {
             if(ServicePointManager.ServerCertificateValidationCallback ==null)
             {
                 ServicePointManager.ServerCertificateValidationCallback += 
                     delegate
                     (
                         Object obj, 
                         X509Certificate certificate, 
                         X509Chain chain, 
                         SslPolicyErrors errors
                     )
                     {
                         return true;
                     };
             }
         }
     }
"@
     Add-Type $certCallback
 }
 [ServerCertificateValidationCallback]::Ignore()

$props = @{};

## Use -SkipCertificateCheck in powershell 6 and above
if ( $PSVersionTable.PSVersion.Major -ge 6 ) {
    $props = @{ SkipCertificateCheck = $true };
}


$urlRoot = "https://$ip/rest/";



## Set the URL for logging in, and the http POST body
$loginUrl = $urlRoot + "login";
$body = @{
    Username = $user;
    Password = $pass;
}

## Log into the server.  The session data (including cookies), is saved in the $websession.
Invoke-WebRequest -uri $loginUrl @props -SessionVariable websession -body $body -Method Post | Out-Null
$props.websession = $websession
$cookies = $websession.Cookies.GetCookies($urlRoot);
$sessid  = $cookies.Value;



## Using documentation from: https://support.sonus.net/display/UXAPIDOC/POST+certificate+-+action+import12
## The following fields are required:
##     CertFileName	- Indicates the name of the file to be uploaded with allowable file type extension such as .pfx or .p12.
##     EncryptedPassword - Identifies the password for the password protected PKCS12 certificate.
$Form = @{
    CertFileName      = Get-Item -Path $P12File;
    EncryptedPassword = $P12Pass
}

$certid = 1; ## Certificate id 1 is reserved for the server certificate (which is our goal here.)
$certUrl = $urlRoot + "certificate/$($certid)?action=import12";
Write-Host "`n`n$certUrl`n`n";
$resp = Invoke-WebRequest @props -Uri $certUrl -Method Post -Form $Form
$resp.Content;

## THIS CURL COMMAND WORKS:
## curl --cookie PHPSESSID=$sessid -k -i "https://$ip/rest/certificate/$($certid)?action=import12" -F "CertFileName=@$P12File" -F "EncryptedPassword=$P12Pass"

## Log out to keep the number of active sessions on the SBC to a minimum.
$logoutUrl = $urlRoot + 'logout'
$resp = Invoke-WebRequest @props -Uri $logoutUrl  -Method Post | Out-Null

<#
.\LoadServerCert.ps1 -ip $ip -user $user -pass $pass -P12File $certfile -P12Pass $certPass

$resp.Content is:

    <?xml version="1.0"?>
    <root>
    <status>
    <http_code>500</http_code>
    <app_status href="https://10.167.8.7/rest/certificate/1">
    <app_status_entry code="15026" params="15000"/>
    </app_status>
    </status>
    </root>

Code 15026 is 'Certificate file data content cannot be empty or exceed the maximum size limit %1%.'



#>
