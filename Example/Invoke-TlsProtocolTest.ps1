PARAM (
    $InputCsvFilePath = 'input.csv',
    $OutputCsvFilePath = 'output.csv'
)
# This is an example of using powershell 7's ForEach-Object -Parallel to spawn off concurrent threads to scan multiple systems simultaneously.
function Invoke-TlsProtocolTest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$InputCsvFilePath,
        [Parameter(Mandatory)][string]$OutputCsvFilePath,
        [Switch]$Force
    )
    
    begin {
        if (-not (Test-Path $InputCsvFilePath)) {
            Write-Error "Cannot find $InputCsvFilePath`." -ErrorAction Stop
        }

        if (Test-Path $OutputCsvFilePath) {
            if ($Force) {
                Remove-Item -Path $OutputCsvFilePath
            }
            else {
                Write-Error "OutputCsvFilePath $OutputCsvFilePath already exists. Use -Force to overwrite." -ErrorAction Stop
            }
        }

        if(-not $ThrottleLimit) {
            if ($isMacOS) {
                [int32]$ThrottleLimit = sysctl -n hw.logicalcpu
                $slash = '/'
                Write-Verbose "isMacOS: $isMacOS`."
            }
            elseif ($isLinux) {
                [int32]$ThrottleLimit = python -c 'import multiprocessing as mp; print(mp.cpu_count())'
                $slash = '/'
                Write-Verbose "isLinux: $isLinux`."
            }
            else {
                try {
                    [int32]$ThrottleLimit = (Get-WmiObject Win32_Processor).Count
                }
                catch {
                    $ThrottleLimit = 5 # Microsoft's default value for ForEach-Object -Parallel
                }
                $slash = '\'
                Write-Verbose "isWindows: $true"
            }
        }
        Write-Verbose "InputCsvFilePath: $InputCsvFilePath"
        Write-Verbose "ThrottleLimit: $ThrottleLimit"
    }
    
    process {
        $ConcurrentDictionary = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
        $Guid = (New-Guid).Guid
        New-Item $Guid -ItemType Directory
        # TO-DO: Add threadsafe ooperation to save output to a single csv file
        # $ConcurrentQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]
        Import-Csv -Path $InputCsvFilePath | ForEach-Object -Parallel {
            $record = $_
            $server = $record.server
            $port = $record.port
            $dictitonary = $using:ConcurrentDictionary
            Write-Verbose "Server: $server"
            Write-Verbose "Port: $port"
            Import-Module "Test-TlsProtocols"
            $tempDir = $using:Guid
            $osSlash = $using:slash
            try {
                $job = Start-Job -ScriptBlock { Test-TlsProtocols -Server $args[0] -Port $args[1] -IncludeRemoteCertificateInfo -IncludeErrorMessages } -ArgumentList $server, $port |
                    Wait-Job -Timeout 30
            }
            catch {
                Add-Content Errors.txt -Value "$server - $port"
            }
            if ($job.State -eq 'Completed') {
                $hashtable = Receive-Job $job
                Remove-Job $job
                $tempFile = $tempDir + $osSlash + $(New-Guid).Guid + '.csv'
                Write-Verbose $tempFile
                $dictitonary.TryAdd($server,$hashtable)
                $psobject = [PSCustomObject]$hashtable
                Export-Csv $tempFile -InputObject $psobject -Encoding utf8
            }
            
        } -ThrottleLimit $ThrottleLimit
        Get-ChildItem $Guid -Filter *.csv | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $OutputCsvFilePath -NoTypeInformation -Append
        Remove-Item $Guid -Recurse
    }
    end {
        Import-Csv $OutputCsvFilePath | ForEach-Object {
            # Do more work based upon results
            $_
        }
    }
} # Invoke-TlsProtocolTest

Invoke-TlsProtocolTest -InputCsvFilePath $InputCsvFilePath -OutputCsvFilePath $OutputCsvFilePath -Force
