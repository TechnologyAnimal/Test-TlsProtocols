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

.PARAMETER Server
    The fully qualified domain name or IP address of the remote computer to connect to.
    * Dns will resolve an ip address to a fully qualified domain name.
    * Using an IP address will technically work, though, a DNS lookup to resolve the server FDQN will be used. If an IP address hosts multiple servers, an unpredictable FQDN will get selected as the FQDN to test. The end result may not get routed to the correct server.

.PARAMETER Port
    A list of remote ports to connect to. The default is 443. Each additional port will return another result.

.PARAMETER ProtocolName
    A list of protocols to test. Requires that the client system supports each protocol to test.
    Some common examples: Tls13, Tls12, Tls11, Tls, Ssl3, Ssl2

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

.PARAMETER OutputFormat
    This will convert the results to the corresponding output object, and if appropriate, and format. See below for a description of what each option returns as. The default is PSObject.

    Csv returns a System.String object in CSV format.
    Json returns a System.String object in JSON format.
    OrderedDictionary returns a System.Collections.Specialized.OrderedDictionary object.
    PSObject returns a System.Management.Automation.PSCustomObject object.
    Xml returns a System.Xml.XmlDocument object.

.PARAMETER WhatIf
    This will list the Server, Ports, and ProtocolNames that would get tested if this switch is omitted or set to false.

.EXAMPLE
    Test-TlsProtocols -Server "github.com" -IncludeRemoteCertificateInfo

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
    Test-TlsProtocols -Server "github.com" -OutputFormat PSObject

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
    Test-TlsProtocols -Server "google.com" -OutputFormat Json

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
    Test-TlsProtocols -Server "google.com" -ReturnRemoteCertificateOnly

    Thumbprint                                Subject              EnhancedKeyUsageList
    ----------                                -------              --------------------
    7D0384E3195E04043DBED29FF58815857278240C  CN=*.google.com, O=…
#>
function Test-TlsProtocols {
    [cmdletbinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Server,
        [int32[]]$Port = 443,
        [string[]]$ProtocolName,
        [string]$InputCsvFilePath,
        [ValidateSet("PSObject", "Csv", "Json", "OrderedDictionary", "Xml")]
        [String]$OutputFormat = "PSObject",
        [switch]$ExportRemoteCertificate,
        [switch]$IncludeErrorMessages,
        [switch]$IncludeRemoteCertificateInfo,
        [switch]$ReturnRemoteCertificateOnly,
        [ValidateSet(1, 2, 3, 4, 5)][int32]$TimeoutSeconds = 2
    )
    begin {
        # Validate input
        # TO-DO: Add client TLS configuration settings validation, i.e. check registry for supported client tls protocols and the *nix equivalent.
        # Check all Ssl/Tls protocols
        $SupportedProtocolNames = ([System.Security.Authentication.SslProtocols]).GetEnumValues().Where{ $_ -ne 'Default' -and $_ -ne 'None' }
        Write-Verbose "Supported tls protocols:"
        $SupportedProtocolNames.ForEach{ Write-Verbose $_ }
        if (-not $ProtocolName){
            Write-Verbose "No tls protocols specified. Defaulting to test all support tls protocols."
            $ProtocolName = $SupportedProtocolNames
        }
        elseif ($UnsupportedProtocolNames = $ProtocolName.Where{ $_ -notin $SupportedProtocolNames }) {
            Write-Verbose "Unsupported tls protocol(s) specified. Unable to complete request. "
            Write-Error -ErrorAction Stop (
                "Unknown protocol name(s). Please use names from the list of protocol names supported on this system ({0}). You used: {1}" -f
                ($SupportedProtocolNames -join ", "),
                ($UnsupportedProtocolNames -join ", ")
            )
        }

        # Resolve input
        if ($Server -as [IPAddress]) {
            try {
                $Fqdn = [System.Net.DNS]::GetHostByAddress($Server).HostName
                $Ip = $Server
                Write-Verbose "Server is an IP address with FQDN: $Fqdn"
            } catch {
                Write-Error "Unable to resolve IP address $Server to fqdn."
            }
        }
        else {
            $Fqdn = $Server
            $Ip = [System.Net.DNS]::GetHostByName($Server).AddressList.IPAddressToString -join ", "
            Write-Verbose "Server is an FQDN with the following IP addresses: $ip"
        }
    }
    process {
        # TO-DO: Add option to enable RemoteCertificateValidationCallback (current implementation accepts all certificates)
        Write-Verbose "Scanning $($port.count) ports:"
        $Port.ForEach{ Write-Verbose $_ }

        $Port.ForEach{
            $p = $_
            $ProtocolStatus = [Ordered]@{
                Fqdn = $Fqdn
                IP   = $Ip
                Port = $p
            }
            [PSCustomObject]$ProtocolStatus.ForEach{ Write-Verbose $_ }
            if ($pscmdlet.ShouldProcess($Server, "Test the following protocols: $Name")) {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $OpenPort = Test-Connection $Server -TCPPort $p -TimeoutSeconds $TimeoutSeconds
                }
                else {
                    $OpenPort = (Test-NetConnection $Server -Port $p).TcpTestSucceeded
                }
                Write-Verbose "Connection to $Server`:$p is available - $OpenPort"
                if ($OpenPort) {
                    # Retrieve remote certificate information when IncludeRemoteCertificateInfo switch is enabled.
                    if ($IncludeRemoteCertificateInfo) {
                        Write-Verbose "Including remote certificate information."
                        $ProtocolStatus += [ordered]@{
                            CertificateThumbprint = 'unknown'
                            CertificateSubject    = 'unknown'
                            CertificateIssuer     = 'unknown'
                            CertificateIssued     = 'unknown'
                            CertificateExpires    = 'unknown'
                            SignatureAlgorithm    = 'unknown'
                        }
                    }
                    $ProtocolName.ForEach{
                        $Name = $_
                        Write-Verbose "Starting test on $Name"
                        $ProtocolStatus.Add($Name, 'unknown')
                        if ($IncludeErrorMessages) {
                            $ProtocolStatus.Add("$Name`ErrorMsg", $false)
                        }
                        try {
                            $Socket = [System.Net.Sockets.Socket]::new([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                            Write-Verbose "Attempting socket connection to $fqdn`:$p"
                            $Socket.Connect($fqdn, $p)
                            Write-Verbose "Connection succeeded."
                            $NetStream = [System.Net.Sockets.NetworkStream]::new($Socket, $true)
                            $SslStream = [System.Net.Security.SslStream]::new($NetStream, $true, { $true }) # Ignore certificate validation errors
                            Write-Verbose "Attempting to authenticate to $fqdn as a client over $Name"
                            $SslStream.AuthenticateAsClient($fqdn, $null, $Name, $false)
                            $ProtocolStatus[$Name] = $true # success
                            Write-Verbose "Successfully authenticated to $fqdn`:$p"
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
                        }
                        catch {
                            $ProtocolStatus[$Name] = $false # failed to establish tls connection
                            Write-Verbose "Unable to establish tls connection with $fqdn`:$p over $Name"
                            # Collect detailed error message about why the tls connection failed
                            if ($IncludeErrorMessages) {
                                $e = $error[0]
                                $NestedException = $e.Exception.InnerException.InnerException.Message
                                if ($NestedException) { $emsg = $NestedException }
                                else { $emsg = $e.Exception.InnerException.Message }
                                Write-Verbose $emsg
                                $ProtocolStatus["$Name`ErrorMsg"] = $emsg
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
                }
                else {
                    # Supported Tls protocols are unknown when a connection cannot be established.
                    Write-Verbose "Supported Tls protocols are unknown when a connection cannot be established."
                    $ProtocolName.ForEach{
                        $Name = $_
                        $ProtocolStatus.Add($Name, 'unknown')
                        if ($IncludeErrorMessages) {
                            $ProtocolStatus.Add("$Name`ErrorMsg", "Could not connect to $server on TCP port $p`.")
                        }
                    }
                }
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat $OutputFormat
            }
        }
    }
} # Test-TlsProtocols

function Export-ProtocolStatus {
    [CmdletBinding()]
    param (
        $ProtocolStatus,
        $OutputFormat = 'PSObject'
    )
    
    process {
        # Various switches to generate output in desired format of choice
        switch ($OutputFormat) {
            "Csv" { [PSCustomObject]$ProtocolStatus | ConvertTo-Csv -NoTypeInformation }
            "Json" { [PSCustomObject]$ProtocolStatus | ConvertTo-Json }
            "OrderedDictionary" { $ProtocolStatus } # Ordered HashTable
            "PSObject" { [PSCustomObject]$ProtocolStatus }
            "Xml" { [PSCustomObject]$ProtocolStatus | ConvertTo-Xml -NoTypeInformation }
        }
    }
}

Export-ModuleMember -Function Test-TlsProtocols