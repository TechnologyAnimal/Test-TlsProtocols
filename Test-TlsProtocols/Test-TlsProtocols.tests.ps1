$ThisModule = $MyInvocation.MyCommand.Path -replace '\.tests\.ps1$'
$ThisModuleName = $ThisModule | Split-Path -Leaf
Get-Module -Name $ThisModuleName -All | Remove-Module -Force -ErrorAction Ignore
Import-Module -Name "$ThisModule.psm1" -Force -ErrorAction Stop

InModuleScope $ThisModuleName {
    Describe Test-TlsProtocols {
        context 'Input' {
            it 'when invalid protocol name is used for input, should throw exception' {
                { Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'invalidprotocol' } | Should throw
            }
            it 'when valid protocol name is used for input, should NOT throw exception' {
                { Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'Tls12' } | Should Not throw
            }
            it 'when invalid IP address is used for input, should throw exception' {
                { Test-TlsProtocols -Server '1.2.3.4.5' -Port 443 } | Should throw
            }
            it 'when valid IP address is used for input, should NOT throw exception' {
                { Test-TlsProtocols -Server '8.8.8.8' -Port 443 } | Should Not throw
            }

            it 'when invalid port is used for input, should throw exception' {
                { Test-TlsProtocols -Server '8.8.8.8' -Port 66000 } | Should throw
            }
        }
    }
    Describe Export-ProtocolStatus {
        context 'Input' {
            $ProtocolStatus = [Ordered]@{
                Fqdn = 'google.com'
                Ip = '216.58.193.78, 2001:4860:4802:34::75'
                Port = '443'
                Ssl2 = $false
                Ssl3 = $false
                Tls = $true
                Tls11 = $true
                Tls12 = $true
                Tls13 = $false
            }
            $json = [PSCustomObject]$ProtocolStatus | ConvertTo-Json
            $csv = ([PSCustomObject]$ProtocolStatus | ConvertTo-Csv -NoTypeInformation)
            $xml = [PSCustomObject]$ProtocolStatus | ConvertTo-Xml -NoTypeInformation
            $psobject = [PSCustomObject]$ProtocolStatus
            it 'when $OutputFormat is Json, should return JSON format' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Json' | Should Match $json
            }

            it 'when $OutputFormat is Csv, should return CSV format' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Csv' | Should Be $csv
            }

            it 'when $OutputFormat is OrderedDictionary, should return OrderedDictionary' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'OrderedDictionary' | Should Match $ProtocolStatus
            }

            it 'when $OutputFormat is XML, should return XML' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Xml' | Should Match $xml
            }

            it 'when $OutputFormat is NOT provided, should return PSObject' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus | Should Match $psobject
            }
        }
        # TO-DO Add tests until code coverage is greater than 80%.
    }
}