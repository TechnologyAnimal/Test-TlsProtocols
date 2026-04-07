$ThisModule = $MyInvocation.MyCommand.Path -replace '\.tests\.ps1$'
$ThisModuleName = $ThisModule | Split-Path -Leaf
Get-Module -Name $ThisModuleName -All | Remove-Module -Force -ErrorAction Ignore
Import-Module -Name "$ThisModule.psm1" -Force -ErrorAction Stop

InModuleScope $ThisModuleName {
    Describe Test-TlsProtocols {
        context 'Input' {
            it 'when invalid protocol name is used for input, should throw exception' {
                { Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'invalidprotocol' } | Should -Throw
            }
            it 'when valid protocol name is used for input, should NOT throw exception' {
                { Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12' } | Should -Not -Throw
            }
            it 'when invalid IP address is used for input, should throw exception' {
                { Test-TlsProtocols -Server '1.2.3.4.5' -Port 443 } | Should -Throw
            }
            it 'when valid IP address is used for input, should NOT throw exception' {
                { Test-TlsProtocols -Server '8.8.8.8' -Port 443 } | Should -Not -Throw
            }

            it 'when invalid port is used for input, should throw exception' {
                { Test-TlsProtocols -Server '8.8.8.8' -Port 66000 } | Should -Throw
            }
        }
        context 'IgnoreCertificateValidation' {
            it 'when IgnoreCertificateValidation is used, should NOT throw exception' {
                { Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12' -IgnoreCertificateValidation } | Should -Not -Throw
            }
            it 'when IgnoreCertificateValidation is not used, should validate certificates by default' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12'
                $result.Tls12 | Should -Be $true
            }
        }
        context 'CipherSuiteReporting' {
            it 'should include CipherAlgorithm in output' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12'
                $result.CipherAlgorithm | Should -Not -BeNullOrEmpty
            }
            it 'should include KeyExchangeAlgorithm in output' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12'
                $result.KeyExchangeAlgorithm | Should -Not -BeNullOrEmpty
            }
        }
        context 'DeprecatedProtocolWarnings' {
            it 'should emit a warning when deprecated protocols are requested' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls' -WarningVariable warn 3>$null
                $warn | Should -Not -BeNullOrEmpty
            }
            it 'should NOT emit a warning for non-deprecated protocols' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12' -WarningVariable warn 3>$null
                $warn | Should -BeNullOrEmpty
            }
        }
        context 'IncludeRemoteCertificateInfo' {
            it 'should include certificate fields in output' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12' -IncludeRemoteCertificateInfo
                $result.CertificateThumbprint | Should -Not -BeNullOrEmpty
                $result.CertificateSubject | Should -Not -BeNullOrEmpty
                $result.CertificateIssuer | Should -Not -BeNullOrEmpty
                $result.CertificateIssued | Should -Not -BeNullOrEmpty
                $result.CertificateExpires | Should -Not -BeNullOrEmpty
                $result.SignatureAlgorithm | Should -Not -BeNullOrEmpty
            }
            it 'should not include certificate fields when switch is omitted' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12'
                $result.CertificateThumbprint | Should -BeNullOrEmpty
            }
        }
        context 'ReturnRemoteCertificateOnly' {
            it 'should return an X509Certificate2 object' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12' -ReturnRemoteCertificateOnly
                $result | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
            }
        }
        context 'IncludeErrorMessages' {
            it 'should include error message fields for failed protocols' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Ssl3' -IncludeErrorMessages -WarningAction SilentlyContinue
                $result.Ssl3 | Should -Be $false
                $result.Ssl3ErrorMsg | Should -Not -Be $false
            }
        }
        context 'MultipleProtocols' {
            it 'should test multiple protocols in a single call' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12', 'Tls13'
                $result.Tls12 | Should -Not -BeNullOrEmpty
                $result.Tls13 | Should -Not -BeNullOrEmpty
            }
        }
        context 'UnreachablePort' {
            it 'should return unknown for protocols when port is unreachable' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 9999 -ProtocolName 'Tls12'
                $result.Tls12 | Should -Be 'unknown'
            }
        }
        context 'WhatIf' {
            it 'should not perform connection when -WhatIf is used' {
                $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12' -WhatIf
                $result | Should -BeNullOrEmpty
            }
        }
        context 'NegotiatedCipherSuite' {
            it 'should include NegotiatedCipherSuite on PS 6+' {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12'
                    $result.NegotiatedCipherSuite | Should -Not -BeNullOrEmpty
                } else {
                    Set-ItResult -Skipped -Because 'NegotiatedCipherSuite is only available on PS 6+'
                }
            }
        }
        context 'FIPSCompliance' {
            it 'should include FIPSCompliant field on PS 6+' {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12'
                    $result.PSObject.Properties.Name | Should -Contain 'FIPSCompliant'
                } else {
                    Set-ItResult -Skipped -Because 'FIPSCompliant requires NegotiatedCipherSuite (PS 6+)'
                }
            }
            it 'should report True for a known FIPS-compliant server' {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12'
                    $result.FIPSCompliant | Should -Be $true
                } else {
                    Set-ItResult -Skipped -Because 'FIPSCompliant requires NegotiatedCipherSuite (PS 6+)'
                }
            }
            it 'should report a boolean value for FIPSCompliant' {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $result = Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12'
                    $result.FIPSCompliant | Should -BeOfType [bool]
                } else {
                    Set-ItResult -Skipped -Because 'FIPSCompliant requires NegotiatedCipherSuite (PS 6+)'
                }
            }
        }
        context 'URLParsing' {
            it 'should accept a full URL and extract host' {
                $result = Test-TlsProtocols -Server 'https://google.com/search?q=test' -ProtocolName 'Tls12'
                $result.Fqdn | Should -Be 'google.com'
            }
            it 'should accept host:port format' {
                $result = Test-TlsProtocols -Server 'google.com:443' -ProtocolName 'Tls12'
                $result.Fqdn | Should -Be 'google.com'
                $result.Port | Should -Be 443
            }
        }
    }
    Describe Export-ProtocolStatus {
        context 'Input' {
            BeforeAll {
                $ProtocolStatus = [Ordered]@{
                    Fqdn = 'google.com'
                    Ip = '216.58.193.78, 2001:4860:4802:34::75'
                    Port = '443'
                    Ssl2 = $false
                    Ssl3 = $false
                    Tls = $true
                    Tls11 = $true
                    Tls12 = $true
                    NegotiatedCipherSuite = 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
                    FIPSCompliant = $true
                    Tls13 = $false
                }
                $json = [PSCustomObject]$ProtocolStatus | ConvertTo-Json
                $csv = ([PSCustomObject]$ProtocolStatus | ConvertTo-Csv -NoTypeInformation)
                $xml = [PSCustomObject]$ProtocolStatus | ConvertTo-Xml -NoTypeInformation
                $psobject = [PSCustomObject]$ProtocolStatus
            }
            it 'when $OutputFormat is Json, should return JSON format' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Json' | Should -Match $json
            }

            it 'when $OutputFormat is Csv, should return CSV format' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Csv' | Should -Be $csv
            }

            it 'when $OutputFormat is OrderedDictionary, should return OrderedDictionary' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'OrderedDictionary' | Should -Match $ProtocolStatus
            }

            it 'when $OutputFormat is XML, should return XML' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Xml' | Should -Match $xml
            }

            it 'when $OutputFormat is NOT provided, should return PSObject' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus | Should -Match $psobject
            }
        }
        # TO-DO Add tests until code coverage is greater than 80%.
    }
}