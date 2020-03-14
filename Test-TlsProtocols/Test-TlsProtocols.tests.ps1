$ThisModule = $MyInvocation.MyCommand.Path -replace '\.tests\.ps1$'
$ThisModuleName = $ThisModule | Split-Path -Leaf
Get-Module -Name $ThisModuleName -All | Remove-Module -Force -ErrorAction Ignore
Import-Module -Name "$ThisModule.psm1" -Force -ErrorAction Stop

InModuleScope $ThisModuleName {
    Describe Test-TlsProtocols {
        context 'Input' {
            it 'when invalid protocol name is used for input, should throw exception' {
                { Test-TlsProtocols -Server 'google.com' -Ports 443 -ProtocolNames 'invalidprotocol' } | Should throw
            }
        }

        # TO-DO Add tests until code coverage is greater than 80%.
    }
}