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

.LINK
    https://www.powershellgallery.com/packages/Test-TlsProtocols

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

.PARAMETER IgnoreCertificateValidation
    Enabling this switch will skip certificate validation when establishing TLS connections. By default, certificate
    validation is enforced. Use this switch only when testing systems with self-signed or otherwise untrusted certificates.

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
    Test-TlsProtocols -Server "github.com" -ProtocolName "Tls12"

    Fqdn                  : github.com
    IP                    : 140.82.116.4
    Port                  : 443
    Tls12                 : True
    NegotiatedCipherSuite : TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    CipherAlgorithm       : Aes128
    CipherStrength        : 128
    KeyExchangeAlgorithm  : DiffieHellman
    KeyExchangeStrength   : 0
    HashAlgorithm         : None
    HashStrength          : 0

.EXAMPLE
    Test-TlsProtocols -Server "github.com" -ProtocolName "Tls12" -IncludeRemoteCertificateInfo

    Fqdn                  : github.com
    IP                    : 140.82.116.4
    Port                  : 443
    CertificateThumbprint : AB58EA128BA92CA69A31B36B4E545653EED2A6CF
    CertificateSubject    : CN=github.com
    CertificateIssuer     : CN=Sectigo Public Server Authentication CA DV E36, O=Sectigo Limited, C=GB
    SignatureAlgorithm    : sha256ECDSA
    Tls12                 : True
    NegotiatedCipherSuite : TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    CipherAlgorithm       : Aes128
    CipherStrength        : 128
    KeyExchangeAlgorithm  : DiffieHellman
    KeyExchangeStrength   : 0
    HashAlgorithm         : None
    HashStrength          : 0

.EXAMPLE
    Test-TlsProtocols -Server "google.com" -ProtocolName "Tls12" -OutputFormat Json

    {
        "Fqdn": "google.com",
        "IP": "142.251.219.14",
        "Port": 443,
        "Tls12": true,
        "NegotiatedCipherSuite": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "CipherAlgorithm": "Aes128",
        "CipherStrength": 128,
        "KeyExchangeAlgorithm": "DiffieHellman",
        "KeyExchangeStrength": 0,
        "HashAlgorithm": "None",
        "HashStrength": 0
    }

.EXAMPLE
    Test-TlsProtocols -Server "google.com" -ReturnRemoteCertificateOnly

    Thumbprint                                Subject              EnhancedKeyUsageList
    ----------                                -------              --------------------
    DE18EF3196486126478F5FEE5FC57EA70F3150C1  CN=*.google.com      {Server Authentication (1.3.6.1.5.5.7.3.1)}
#>
function Test-TlsProtocols {
    [cmdletbinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Server,
        [ValidateRange(1,65535)]
        [int32[]]$Port = 443,
        [string[]]$ProtocolName,
        [ValidateSet("PSObject", "Csv", "Json", "OrderedDictionary", "Xml")]
        [String]$OutputFormat = "PSObject",
        [switch]$ExportRemoteCertificate,
        [switch]$IncludeErrorMessages,
        [switch]$IncludeRemoteCertificateInfo,
        [switch]$ReturnRemoteCertificateOnly,
        [switch]$IgnoreCertificateValidation,
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
        # Warn about deprecated protocols
        $DeprecatedProtocols = @('Ssl2', 'Ssl3', 'Tls', 'Tls11')
        $RequestedDeprecated = $ProtocolName.Where{ $_ -in $DeprecatedProtocols }
        if ($RequestedDeprecated) {
            Write-Warning ("The following protocols are deprecated and insecure (RFC 8996): {0}. Consider using Tls12 or Tls13." -f ($RequestedDeprecated -join ', '))
        }

        # FIPS 140-3 approved cipher suites per NIST SP 800-52 Rev 2.
        # See FIPS.md for the full reference and rationale.
        $FIPSApprovedCipherSuites = @(
            # TLS 1.2 required (ECDHE + AES-GCM)
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
            # TLS 1.2 recommended (ECDHE + AES-CBC)
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
            # TLS 1.2 recommended (DHE + AES-GCM)
            'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
            'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
            # TLS 1.3 (AES-GCM only; ChaCha20 is not FIPS-approved)
            'TLS_AES_128_GCM_SHA256'
            'TLS_AES_256_GCM_SHA384'
            'TLS_AES_128_CCM_SHA256'
        )

        # Parse URL if a full URL was provided (e.g. https://host:port/path)
        # TLS handshakes use only host+port; the path is an HTTP-layer concept and is ignored.
        if ($Server -match '^https?://') {
            try {
                $ParsedUri = [System.Uri]::new($Server)
                Write-Verbose "Parsed URL: host=$($ParsedUri.Host), port=$($ParsedUri.Port), path=$($ParsedUri.AbsolutePath) (path ignored)"
                $Server = $ParsedUri.Host
                if ($ParsedUri.Port -and $ParsedUri.Port -ne 443 -and $ParsedUri.Port -ne -1) {
                    $Port = @($ParsedUri.Port)
                }
            }
            catch {
                Write-Warning "Unable to parse URL '$Server'. Using as-is."
            }
        }
        elseif ($Server -match '^([^/:]+):(\d+)') {
            # Handle host:port/path without scheme
            $Server = $Matches[1]
            $Port = @([int32]$Matches[2])
            Write-Verbose "Parsed host:port — server=$Server, port=$Port"
        }

        if ($Server -as [IPAddress]) {
            try {
                $Fqdn = [System.Net.DNS]::GetHostEntry($Server).HostName
                $Ip = $Server
                Write-Verbose "Server is an IP address with FQDN: $Fqdn"
            } 
            # TO-DO: Should skip process block, but the code gets messy when accounting for all switches to keep objects the same.
            # This is important when results are exported to a csv file.
            catch {
                Write-Verbose "Unable to resolve IP address $Server to fqdn."
            }
        }
        else {
            $Fqdn = $Server
            try {
                $DnsEntry = [System.Net.DNS]::GetHostEntry($Server)
                if ($DnsEntry.AddressList) {
                    $Ip = $DnsEntry.AddressList.IPAddressToString -join ", "
                }
                Write-Verbose "Server is an FQDN with the following IP addresses: $Ip"
            }
            catch [System.Net.Sockets.SocketException] {
                Write-Error -ErrorAction Stop "Unable to resolve server '$Server': $($_.Exception.Message)"
            }
        }
    }
    process {
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
            if ($pscmdlet.ShouldProcess($Server, "Test the following protocols: $($ProtocolName -join ', ')")) {
                try {
                    if ($PSVersionTable.PSVersion.Major -ge 6) {
                        $OpenPort = Test-Connection $Server -TCPPort $p -TimeoutSeconds $TimeoutSeconds
                    }
                    else {
                        $OpenPort = (Test-NetConnection $Server -Port $p).TcpTestSucceeded
                    }
                }
                catch {
                    $OpenPort = $false
                    Write-Verbose "Port test failed: $($_.Exception.Message)"
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
                            if ($IgnoreCertificateValidation) {
                                $SslStream = [System.Net.Security.SslStream]::new($NetStream, $true, { $true })
                            }
                            else {
                                $SslStream = [System.Net.Security.SslStream]::new($NetStream, $true)
                            }
                            Write-Verbose "Attempting to authenticate to $fqdn as a client over $Name"
                            $SslStream.AuthenticateAsClient($fqdn, $null, $Name, $false)
                            $ProtocolStatus[$Name] = $true # success
                            Write-Verbose "Successfully authenticated to $fqdn`:$p"

                            # Report negotiated cipher suite information if available
                            if ($PSVersionTable.PSVersion.Major -ge 6) {
                                try {
                                    $NegotiatedSuite = $SslStream.NegotiatedCipherSuite.ToString()
                                    $ProtocolStatus["NegotiatedCipherSuite"] = $NegotiatedSuite
                                    $ProtocolStatus["FIPSCompliant"] = $NegotiatedSuite -in $FIPSApprovedCipherSuites
                                    Write-Verbose "Negotiated cipher suite: $NegotiatedSuite (FIPS: $($ProtocolStatus['FIPSCompliant']))"
                                }
                                catch {
                                    Write-Verbose "NegotiatedCipherSuite property not available on this runtime."
                                }
                            }
                            if (-not $ProtocolStatus.Contains("CipherAlgorithm")) {
                                try {
                                    $ProtocolStatus["CipherAlgorithm"] = $SslStream.CipherAlgorithm.ToString()
                                    $ProtocolStatus["CipherStrength"] = $SslStream.CipherStrength
                                    $ProtocolStatus["KeyExchangeAlgorithm"] = $SslStream.KeyExchangeAlgorithm.ToString()
                                    $ProtocolStatus["KeyExchangeStrength"] = $SslStream.KeyExchangeStrength
                                    $ProtocolStatus["HashAlgorithm"] = $SslStream.HashAlgorithm.ToString()
                                    $ProtocolStatus["HashStrength"] = $SslStream.HashStrength
                                }
                                catch {
                                    Write-Verbose "Detailed cipher properties not available on this platform: $($_.Exception.Message)"
                                }
                            }

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
                                    if ($PSVersionTable.PSVersion.Major -ge 6) {
                                        $RemoteCertificate.Export('Cert') | Set-Content "$fqdn.cer" -AsByteStream
                                    }
                                    else {
                                        $RemoteCertificate.Export('Cert') | Set-Content "$fqdn.cer" -Encoding Byte
                                    }
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
                                $NestedException = $_.Exception.InnerException.InnerException.Message
                                if ($NestedException) { $emsg = $NestedException }
                                else { $emsg = $_.Exception.InnerException.Message }
                                Write-Verbose $emsg
                                $ProtocolStatus["$Name`ErrorMsg"] = $emsg
                            }
                        }
                        finally {
                            # Free up system memory/garbage collection
                            Write-Verbose "Garbage collection."
                            try {
                                if ($SslStream) { $SslStream.Dispose() }
                                if ($NetStream) { $NetStream.Dispose() }
                                if ($Socket) { $Socket.Dispose() }
                            }
                            catch {
                                Write-Verbose "Cleanup error: $($_.Exception.Message)"
                            }
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
        $OutputFormat
    )
    
    process {
        if ([string]::IsNullOrWhiteSpace($OutputFormat)) {
            [PSCustomObject]$ProtocolStatus
        } else {
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
}

Export-ModuleMember -Function Test-TlsProtocols