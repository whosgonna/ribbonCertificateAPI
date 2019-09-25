## Issue with uploading pfx files to Ribbon SWeLite using the API.


All examples assume that the gateway's IP address is `10.167.8.7`, and that the
API user name is `restApiUser` with a password of `P@ssW0rd`;

### Example 1:  Uploading a trusted root certificate (.pem format) via the API 

```LoadTrustedCert.ps1```

**This example works and is provided for contrast to the examples that fail.**

This is a fairly straight forward **working** example.  The certifiate data for the 
Baltimore CyberTrust Root certificate is base64 data, so it's written directly
into the script.  This is the certificate used by Microsoft on their Teams
endpoints, so this certificate must be loaded as a trusted root certificate for
any connection to Teams.

In this example, the certificate data is base64, so it's put directly into the body
of the request.  The script can be run as follows:

```powershell
.\LoadTrustedCert -ip '10.167.8.7' -user 'restApiUser' -pass 'P@ssW0rd'
```


### Example 2:  Uploading a pfx file as the server certificate.

```LoadServerCert.psq```

**This example fails.**

This example is based very literally off of the documentation for importing a pfx
file (https://support.sonus.net/display/UXAPIDOC/POST+certificate+-+action+import12), 
which lists only two parameters, `CertFileName` and `EncryptedPassword`.  If the 
certificate file is `C:\certificate.pfx` with a password of `C3rtP@ss`, the script
would be executed as follows:

```powershell
.\LoadServerCert.ps1 -ip '10.167.8.7' -user 'restApiUser' -pass 'P@ssW0rd' -P12File 'C:\certificate.pfx' -P12Pass 'C3rtP@ss'
```

This fails with a code of `15026 - Certificate file data content cannot be empty or 
exceed the maximum size limit %1%.`.  This isn't really shocking since the actual
data for the certificate and key is not transmitted anywhere in this process.  It's
not possible to send a web server the name of a local file and have the web server
just read the file.

