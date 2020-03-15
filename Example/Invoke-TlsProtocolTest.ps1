# This is an example of using powershell 7's ForEach-Object -Parallel to spawn off concurrent threads to scan multiple systems simultaneously.
function Invoke-TlsProtocolTest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$InputCsvFilePath,
        [int32]$ThrottleLimit
    )
    
    begin {
        if (-not (Test-Path $InputCsvFilePath)) {
            Write-Error "Cannot find $InputCsvFilePath`." -ErrorAction Stop
        }
        if(-not $ThrottleLimit) {
            if ($isWindows) {
                Write-Verbose "isWindows: $isWindows"
                [int32]$ThrottleLimit = (Get-WmiObject Win32_Processor).Count
            }
            elseif ($isMacOS) {
                [int32]$ThrottleLimit = sysctl -n hw.logicalcpu
                Write-Verbose "isMacOS: $isMacOS`."
            }
            elseif ($isLinux) {
                [int32]$ThrottleLimit = python -c 'import multiprocessing as mp; print(mp.cpu_count())'
                Write-Verbose "isLinux: $isLinux`."
            }
            else {
                $ThrottleLimit = 5 # Microsoft's default value for ForEach-Object -Parallel
                Write-Verbose "Cannot determine OS."
            }
        }
        Write-Verbose "InputCsvFilePath: $InputCsvFilePath"
        Write-Verbose "ThrottleLimit: $ThrottleLimit"
    }
    
    process {
        $ConcurrentDictionary = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
        # TO-DO: Add threadsafe ooperation to save output to a single csv file
        # $ConcurrentQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]
        Import-Csv -Path $InputCsvFilePath | ForEach-Object -Parallel {
            $record = $_
            $server = $record.server
            $port = $record.port
            $dictitonary = $using:ConcurrentDictionary
            Write-Verbose "Fqdn: $fqdn"
            Write-Verbose "Ports: $ports"
            Import-Module "../Test-TlsProtocols/Test-TlsProtocols.psm1"
            $result = Test-TlsProtocols -Server $server -Port $Port -IncludeRemoteCertificateInfo
            $dictitonary.TryAdd($server,$result)
        } -ThrottleLimit $ThrottleLimit
    }
    end {
        $ConcurrentDictionary
    }
} # Invoke-TlsProtocolTest
if (-not (Get-Module 'Test-TlsProtocols')) {
    Import-Module 'Test-TlsProtocols'
}
$InputCsvFilePath = 'example.csv'
$ThrottleLimit = 8
Invoke-TlsProtocolTest -InputCsvFilePath $InputCsvFilePath -ThrottleLimit $ThrottleLimit
