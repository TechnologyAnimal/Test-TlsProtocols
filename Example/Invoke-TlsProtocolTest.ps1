# This is an example of using powershell 7's ForEach-Object -Parallel to spawn off concurrent threads to scan multiple systems simultaneously.
$InputPath = 'example.csv'
$ThrottleLimit = '8'
$dictionary = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
if ($InputPath) {
    Import-Csv -Path $InputPath | ForEach-Object -Parallel {
        $record = $_
        $server = $record.server
        $ports = $record.ports
        $dict = $using:dictionary
        Write-Verbose "Fqdn: $fqdn"
        Write-Verbose "Ports: $ports"
        Import-Module "../Test-TlsProtocols/Test-TlsProtocols.psm1"
        $result = Test-TlsProtocols -Server $server -Ports $Ports -IncludeRemoteCertificateInfo
        $dict.TryAdd($server,$result)
    } -ThrottleLimit $ThrottleLimit
    $dictionary["github.com"]
    # TO-DO: Add threadsafe ooperation to save output to a single csv file
}