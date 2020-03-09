<#
 .DESCRIPTION
   Outputs the SSL/TLS protocols that the client is able to successfully use to connect to a server using fqdn or ip.
   Optionally outputs remote certificate information.
   Optionally exports remote certificates in .cer format.
 
 .NOTES
    Special thanks to Chris Duck's hard work from 2014 that inspired me to get started on this project.
    You can learn more about it on his blog at

        http://blog.whatsupduck.net/2014/10/checking-ssl-and-tls-versions-with-powershell.html
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

.LINK
    https://github.com/TechnologyAnimal/Test-TlsProtocols
 
.PARAMETER Fqdn
    The fully qualified domain name of the remote computer to connect to.

.PARAMETER Ports
    A list of remote ports to connect to. The default is 443. Each additional port will return another result.

.PARAMETER Ip
    An ip address to connect to. Dns will resolve an ip address to a fully qualified domain name.
    The result of the dns query will be used if a fqdn was not provided as input.

.PARAMETER IncludeErrorMessages
    This switch will include detailed error messages about failed connections for each tls protocol.

.PARAMETER IncludeRemoteCertificateInfo
    This switch will return CertificateThumbprint, CertificateSubject, CertificateIssuer, CertificateIssued,
    CertificateExpires and SignatureAlgorithm in addition to tls protocol information.

.PARAMETER ReturnRemoteCertificateOnly
    Enabling this switch will only return the remote system's certificate as a System.Security.Cryptography.X509Certificates.X509Certificate2 object.

.PARAMETER ExportRemoteCertificate
    Enabling this switch will export the remote system's certificate as a $fqdn.cer file in the path of this script.

.PARAMETER TimeoutSeconds
    This will set the amount of seconds to wait on Test-Connection results before determining the system is unreachable.
    If a remote system port is unreachable, the script will not attempt to establish a socket connection and all supported
    protocols will be unknown. Default value is 2 seconds.

.PARAMETER AsCSV
    Enabling this switch will output the results in System.String object in CSV format.

.PARAMETER AsHashTable
    Enabling this switch will output the results as a System.Collections.Hashtable object.

.PARAMETER AsJson
    Enabling this switch will output the results as a System.String object in JSON format.

.PARAMETER AsOrderedDictionary
    Enabling this switch will output the results as a System.Collections.Specialized.OrderedDictionary object.

.PARAMETER AsPSObject
    Enabling this switch will output the results as a System.Management.Automation.PSCustomObject object. This is default.

.PARAMETER AsXML
    Enabling this switch will output the results as a System.Xml.XmlDocument object.

.EXAMPLE
    Test-TlsProtocols -Fqdn "github.com" -IncludeRemoteCertificateInfo

    Fqdn                  : github.com
    IP                    : 192.30.253.113
    Port                  : 443
    CertificateThumbprint : CA06F56B258B7A0D4F2B05470939478651151984
    CertificateSubject    : CN=github.com, O="GitHub, Inc.", L=San Francisco, S=California, C=US, SERIALNUMBER=5157550, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US, OID.2.5.4.15=Private 
                            Organization
    CertificateIssuer     : CN=DigiCert SHA2 Extended Validation Server CA, OU=www.digicert.com, O=DigiCert Inc, C=US
    CertificateIssued     : 5/7/2018 5:00:00 PM
    CertificateExpires    : 6/3/2020 5:00:00 AM
    SignatureAlgorithm    : sha256RSA
    Ssl2                  : False
    Ssl3                  : False
    Tls                   : False
    Tls11                 : False
    Tls12                 : True
    Tls13                 : True

.EXAMPLE
    Test-TlsProtocols -Fqdn "github.com" -AsPSObject

    Fqdn  : github.com
    IP    : 140.82.114.3
    Port  : 443
    Ssl2  : False
    Ssl3  : False
    Tls   : False
    Tls11 : False
    Tls12 : True
    Tls13 : True

.EXAMPLE
    Test-TlsProtocols -Fqdn "google.com" -AsJson

    {
        "Fqdn": "google.com",
        "IP": "216.239.34.117",
        "Port": 443,
        "Ssl2": false,
        "Ssl3": false,
        "Tls": true,
        "Tls11": true,
        "Tls12": true,
        "Tls13": true
    }

.Example
    Test-TlsProtocols -Fqdn "google.com" -ReturnRemoteCertificateOnly

    Thumbprint                                Subject              EnhancedKeyUsageList
    ----------                                -------              --------------------
    7D0384E3195E04043DBED29FF58815857278240C  CN=*.google.com, O=… 
#>
function Test-TlsProtocols {                         
    param(
        [Parameter(Mandatory=$false)][string]$Fqdn,
        [Parameter(Mandatory=$false)][int32[]]$Ports = 443,
        [Parameter(Mandatory=$false)][string]$Ip,
        [Parameter(Mandatory=$false)][switch]$AsCSV,
        [Parameter(Mandatory=$false)][switch]$AsHashTable,
        [Parameter(Mandatory=$false)][switch]$AsJson,
        [Parameter(Mandatory=$false)][switch]$AsOrderedDictionary,
        [Parameter(Mandatory=$false)][switch]$AsPSObject,
        [Parameter(Mandatory=$false)][switch]$AsXml,
        [Parameter(Mandatory=$false)][switch]$ExportRemoteCertificate,
        [Parameter(Mandatory=$false)][switch]$IncludeErrorMessages,
        [Parameter(Mandatory=$false)][switch]$IncludeRemoteCertificateInfo,
        [Parameter(Mandatory=$false)][switch]$ReturnRemoteCertificateOnly,
        [Parameter(Mandatory=$false)][ValidateSet(1,2,3,4,5)][int32]$TimeoutSeconds = 2
    )
    begin {
        # Validate input
        if ([string]::IsNullOrWhiteSpace($Fqdn) -and [string]::IsNullOrWhiteSpace($Ip)) {
            Write-Error "`$Fqdn and `$Ip are both `$null`. At least one of these parameters is required to test ssl protocols." -ErrorAction Stop
        }
        if (-not $Ip) {
            Write-Verbose "No ip as input."
            $Ip = [System.Net.DNS]::GetHostByName($Fqdn).AddressList.IPAddressToString | Select-Object -First 1
            Write-Verbose "Ip is $ip"
        }
        if (-not $Fqdn) {
            Write-Verbose "No fqdn as input."
            $Fqdn = [System.Net.DNS]::GetHostByAddress($ip).HostName
            Write-Verbose "Fqdn is $fqdn"
        }
        # TO-DO: Add client TLS configuration settings validation, i.e. check registry for supported client tls protocols and the *nix equivalent.
        # Check all Ssl/Tls protocols
        $ProtocolNames = ([System.Security.Authentication.SslProtocols]).GetEnumValues().Where{$_ -ne 'Default' -and $_ -ne 'None'} # Tls13, Tls12, Tls11, Tls, Ssl3, Ssl2
        Write-Verbose "Supported tls protocols:"
        $ProtocolNames | ForEach-Object { Write-Verbose "$_"}
    }
    process {
        # TO-DO: Add option to enable RemoteCertificateValidationCallback (current implementation accepts all certificates)
        Write-Verbose "Scanning $($ports.count) ports:"
        $ports | ForEach-Object { Write-Verbose "$_"}
        foreach ($Port in $Ports) {
            # Create Custom Object to store TLS Protocol Status
            $ProtocolStatus = [Ordered]@{}
            $ProtocolStatus.Add("Fqdn", $Fqdn)
            $ProtocolStatus.Add("IP", $Ip)
            $ProtocolStatus.Add("Port", $Port)
            [PSCustomObject]$ProtocolStatus | ForEach-Object { Write-Verbose "$_"}
            $OpenPort = Test-Connection $Fqdn -TCPPort $Port -TimeoutSeconds $TimeoutSeconds
            Write-Verbose "Connection to $fqdn`:$port is available - $OpenPort"
            if ($OpenPort) {
                # Retrieve remote certificate information when IncludeRemoteCertificateInfo switch is enabled.
                if ($IncludeRemoteCertificateInfo) {
                    Write-Verbose "Including remote certificate information."
                    $ProtocolStatus.Add("CertificateThumbprint", 'unknown')
                    $ProtocolStatus.Add("CertificateSubject", 'unknown')
                    $ProtocolStatus.Add("CertificateIssuer", 'unknown')
                    $ProtocolStatus.Add("CertificateIssued", 'unknown')
                    $ProtocolStatus.Add("CertificateExpires", 'unknown')
                    $ProtocolStatus.Add("SignatureAlgorithm", 'unknown')
                }

                $ProtocolNames | ForEach-Object {
                    $ProtocolName = $_
                    Write-Verbose "Starting test on $ProtocolName"
                    $ProtocolStatus.Add($ProtocolName, 'unknown')
                    if ($IncludeErrorMessages) {
                        $ProtocolStatus.Add("$ProtocolName`ErrorMsg", $false)
                    }
                    try {
                        $Socket = [System.Net.Sockets.Socket]::new([System.Net.Sockets.SocketType]::Stream,[System.Net.Sockets.ProtocolType]::Tcp)
                        Write-Verbose "Attempting socket connection to $fqdn`:$port"
                        $Socket.Connect($fqdn, $Port)
                        Write-Verbose "Connection succeeded."
                        $NetStream = [System.Net.Sockets.NetworkStream]::new($Socket, $true)
                        $SslStream = [System.Net.Security.SslStream]::new($NetStream, $true, {$true}) # Ignore certificate validation errors
                        Write-Verbose "Attempting to authenticate to $fqdn as a client over $ProtocolName"
                        $SslStream.AuthenticateAsClient($fqdn, $null, $ProtocolName, $false)
                        $ProtocolStatus[$ProtocolName] = $true # success
                        Write-Verbose "Successfully authenticated to $fqdn`:$port"
                        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate

                        if ($IncludeRemoteCertificateInfo) {
                            # Store remote certificate information if it hasn't already been collected
                            if ($ProtocolStatus.CertificateThumbprint -eq 'unknown' -and $RemoteCertificate.Thumbprint) {
                                $ProtocolStatus["CertificateThumbprint"] = $RemoteCertificate.Thumbprint
                                $ProtocolStatus["CertificateSubject"] = $RemoteCertificate.Subject
                                $ProtocolStatus["CertificateIssuer"] = $RemoteCertificate.Issuer
                                $ProtocolStatus["CertificateIssued"] = $RemoteCertificate.NotBefore
                                $ProtocolStatus["CertificateExpires"] = $RemoteCertificate.NotAfter
                                $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.SignatureAlgorithm.FriendlyName
                            }
                        }

                        if ($ExportRemoteCertificate) {
                            $CertPath = "$fqdn.cer"
                            if (-not (Test-Path $CertPath)) {
                                Write-Host "Exporting $fqdn.cer to $($(Get-Location).path)" -ForegroundColor Green
                                $RemoteCertificate.Export('Cert') | Set-Content "$fqdn.cer" -AsByteStream
                            }
                        }

                        if ($ReturnRemoteCertificateOnly) {
                            Write-Verbose "Returning $fqdn remote certificate only."
                            $RemoteCertificate
                            break;
                        }
                    } catch {
                        $ProtocolStatus[$ProtocolName] = $false # failed to establish tls connection
                        Write-Verbose "Unable to establish tls connection with $fqdn`:$port over $ProtocolName"
                        # Collect detailed error message about why the tls connection failed
                        if ($IncludeErrorMessages) {
                            $e = $error[0]
                            $NestedException = $e.Exception.InnerException.InnerException.Message
                            if ($NestedException) { $emsg = $NestedException }
                            else { $emsg = $e.Exception.InnerException.Message }
                            Write-Verbose $emsg
                            $ProtocolStatus["$ProtocolName`ErrorMsg"] =  $emsg
                        }
                    }
                    finally {
                        # Free up system memory/garbage collection
                        Write-Verbose "Garbage collection."
                        if ($SslStream) { $SslStream.Dispose() }
                        if ($NetStream) { $NetStream.Dispose() }
                        if ($Socket) { $Socket.Dispose() }
                    }
                }
            } else {
                # Supported Tls protocols are unknown when a connection cannot be established.
                Write-Verbose "Supported Tls protocols are unknown when a connection cannot be established."
                $ProtocolNames | ForEach-Object {
                    $ProtocolName = $_
                    $ProtocolStatus.Add($ProtocolName, 'unknown')
                    if ($IncludeErrorMessages) {
                        $ProtocolStatus.Add("$ProtocolName`ErrorMsg", "Could not connect to $fqdn on TCP port $port`.")
                    }
                }
            }

            # Various switches to generate output in desired format of choice
            if ($AsCSV) { [PSCustomObject]$ProtocolStatus | ConvertTo-Csv -NoTypeInformation }
            if ($AsHashTable) { [hashtable]$ProtocolStatus }
            if ($AsJson) { [PSCustomObject]$ProtocolStatus | ConvertTo-Json }
            if ($AsOrderedDictionary) { $ProtocolStatus }
            if ($AsPSObject) { [PSCustomObject]$ProtocolStatus }
            if ($AsXml) { [PSCustomObject]$ProtocolStatus | ConvertTo-Xml -NoTypeInformation }

            # Default to PSObject
            if ($AsCsv -eq $false -and $AsHashTable -eq $false -and $AsJson -eq $false -and $AsOrderedDictionary -eq $false -and $AsPSObject -eq $false -and $AsXml -eq $false) {
                Write-Verbose "Returning in default format - PSOBject."
                [PSCustomObject]$ProtocolStatus
            }
        }
    }
}
