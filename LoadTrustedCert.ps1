param(
    [Parameter(Mandatory=$true)] $ip,
    [Parameter(Mandatory=$true)] $user,
    [Parameter(Mandatory=$true)] $pass
)



 ## Skip certificate validation.  This part is lengthly, but necessary since there is no
 ## publicly trusted certificate installed on the SBC.
 [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
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

#$systemUrl =  $urlRoot + "system"
#$system_info = Invoke-WebRequest -WebSession $websession -Uri $systemUrl  -Method Get
#$xml = [xml]$system_info.Content.Trim();

## Import a trusted root certificate;
$certid = 2; # Certificate #1 is the server cert, so we're using #2 here.
$certUrl = $urlRoot + "certificate/$($certid)?action=import";

## This is the content (base64) of the Baltimore CyberTrust Root certificate
## that microsoft uses for Teams.  This trusted root certificate must be installed
## for any usage with Teams.
$certData = '-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ
RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD
VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX
DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y
ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy
VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr
mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr
IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK
mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu
XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy
dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye
jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1
BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92
9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx
jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0
Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz
ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS
R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp
-----END CERTIFICATE-----
';


## The body of the POST message for loading a .pem certificate must have
## The CertFileOperation value set to '1', and the CertFileContent 
## argument with the content fo the certificate
$body = @{
    CertFileOperation = 1;
    CertFileContent   = $certData;
}

$resp = Invoke-WebRequest @props -Uri $certUrl -Method Post -Body $body
$resp.Content;

## Log out to keep the number of active sessions on the SBC to a minimum.
$logoutUrl = $urlRoot + 'logout'
Invoke-WebRequest @props -Uri $logoutUrl  -Method Post | Out-Null

