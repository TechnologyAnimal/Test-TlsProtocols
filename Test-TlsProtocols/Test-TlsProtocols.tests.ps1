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
            it 'when invalid protocol name is used for input, should throw exception' {
                { Test-TlsProtocols -Server 'google.com' -Port 443 -ProtocolName 'invalidprotocol' } | Should throw
            }
        }
        # TO-DO Add tests until code coverage is greater than 80%.
    }
    Describe Export-ProtocolStatus {
        context 'Input' {
            $ProtocolStatus = [PSCustomObject][Ordered]@{
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
            $json = $ProtocolStatus | ConvertTo-Json
            $csv = $ProtocolStatus | ConvertTo-Csv -NoTypeInformation
            it 'when $OutputFormat is Json, should return JSON format' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Json' | Should Be $json
            }

            it 'when $OutputFormat is Csv, should return CSV format' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Csv' | Should Be $csv
            }

            it 'when $OutputFormat is provided, should return null' {
                Export-ProtocolStatus -ProtocolStatus $ProtocolStatus -OutputFormat 'Json' | Should Not Be $null
            }
        }
        # TO-DO Add tests until code coverage is greater than 80%.
    }
}