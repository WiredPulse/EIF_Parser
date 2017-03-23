#Requires -runasadministrator

<#
.SYNOPSIS
    Runs EvilInjectFinder.exe and manipulates output in order to show only injects containing 'Yes' in the MZ or DOS column and the computername of the system. This 
    will allow you to only see the items of interest and not get bombarded will all the injects with the EXCUTE_READWRITE permission.  
    
.PARAMETER ComputerName
    Specify a single IP or a text file containing multiple IPs.

.PARAMETER EIF_Path
    Specifiy path to evilinjectfinder.exe.

.EXAMPLE
    .\eif_parser.ps1 -ComputerName c:\users\blue\desktop\computers.txt -EIF_Path "C:\users\blue\desktop\evilinjectfinder.exe"

    Running EvilInjectFinder on the specified IPs in computers.txt 

.EXAMPLE
    .\eif_parser.ps1 -ComputerName 192.168.10.26 -EIF_Path "C:\users\blue\desktop\evilinjectfinder.exe"

    Running EvilInjectFinder a specified IP.

.EXAMPLE
    .\eif_parser.ps1 -ComputerName 127.0.0.1 -EIF_Path "C:\users\blue\desktop\evilinjectfinder.exe"

    Running EvilInjectFinder on the local machine. 

.OUTPUTS
    ComputerName: HUNTER
    Analysing PID: 3116 : notepad.exe
    ATTENTION! PID is protected!
    +------------------------------------------------------------------------------------------------------------------------------+
    |      Address | Permissions       |          Size | Module       | MZ  | DOS | Nops | Sigs | MD5                              |
    +------------------------------------------------------------------------------------------------------------------------------+
    |       370000 | EXECUTE_READWRITE |      128.00KB |              | Yes | Yes |   0% |    0 | C18B486905510DB111B66850FBE1A160 |
    |       db0000 | EXECUTE_READWRITE |      936.00KB |              |  No | Yes |   0% |    0 | 8112F5D9F0AECA304DCD1067637DA38A |
    |      1210000 | EXECUTE_READWRITE |      964.00KB |              | Yes | Yes |   0% |    0 | C1E8250A8B54B3B7F652026CB61E7196 |
    |      13f0000 | EXECUTE_READWRITE |      396.00KB |              | Yes | Yes |   0% |    0 | 844788136F07F31D5D2E261B509B66ED |
    +------------------------------------------------------------------------------------------------------------------------------+

.NOTES
    Version:        1.0
    Author:         @wiredPulse or @Wired_Pulse
    Creation Date:  March 21, 2017

.LINK
    EvilInjectFinder.exe can be found at https://github.com/psmitty7373/eif

#>

param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$EIF_Path
     )

$newline = "`r`n"
New-Item .\EIF_Results -ItemType directory -ErrorAction SilentlyContinue | out-null
$ErrorActionPreference = "silentlycontinue"

function EIF_CALL
    {
    write-host "Starting process on specified systems..." -ForegroundColor Cyan
    foreach($computer in $Cpu)
        {
        # Deletes directory we are copying if it already exists on distant machine
        if (!(test-path "\\$computer\c$\evilinjectfinder.exe"))
            {
            if(!(test-path "\\$computer\c$\"))
                {
                "$computer : No connection path" >> .\EIF_Results\_Log.txt
                }
            copy-item $EIF_Path \\$computer\c$\ -force -ErrorAction SilentlyContinue 
            }
        $proc = Invoke-WmiMethod -ComputerName $computer -Class Win32_Process -Name Create -ArgumentList "powershell /c c:\evilinjectfinder.exe | out-file c:\$computer-5.txt"
        $my_var = Register-WmiEvent -ComputerName $computer -Query "Select * from Win32_ProcessStopTrace Where ProcessID=$($proc.ProcessId)" -MessageData $computer -Action { Write-Host "$($Event.MessageData) Process ExitCode: $($event.SourceEventArgs.NewEvent.ExitStatus)"} 
            if($proc.processid -ne $null)
            {
            # Does nothing
            }
        elseif($proc.processid -eq $null)
            {
            "$computer : Not accessible via WMI" >> .\EIF_Results\_Log.txt
            }
        }
    sleep 30 
    }


Function EIF_RETRIEVE
    {
    foreach($computer in $Cpu)
        {
        # Retrieves the results from the distant machine and saves it locally
        copy-Item \\$computer\c$\$computer-5.txt .\eif_results -force -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\$computer-5.txt -ErrorAction SilentlyContinue
        remove-item \\$computer\c$\evilinjectfinder.exe -ErrorAction SilentlyContinue
        $eif_array = get-content .\eif_results\$computer-5.txt
        foreach($line in $eif_array)
            {
            $eif_str += $line + $newline
            }
        # Split text and only grab the chunk(s) containing 'yes'
        $eif = $eif_str -split "`n`r" | Sls 'yes'

        # File manipulation and output to file
        $eif_cvrt = [string]$eif
        if ($eif_cvrt -eq $null)
            {
            "Nothing malicious detected on $computer" >> .\eif_results\_EIF-Log.txt
            }
        elseif($eif_cvrt -ne $null)
            {
            $eif_out = $eif_cvrt.Replace('Analysing', $newlinw +$newline + 'ComputerName: ' + $computer + $newline  + 'Analysing') | out-file .\eif_results\$computer-EIF.txt
            }
        }

    write-host "Retrieving data..." -ForegroundColor Cyan
    sleep 15
    remove-item .\eif_results\*5.txt
    }


$eif_array = get-content .\eif_results\$computer-5.txt
    foreach($line in $eif_array)
    {
    $eif_str += $line + $newline
    }


function EIF_LOCALHOST
    {
    # Split text and only grab the chunk(s) containing 'yes'
    $eif = $eif_str -split "`n`r" | Sls 'yes'

    # File manipulation and output to file
    $eif_cvrt = [string]$eif
    if ($eif_cvrt -eq $null)
        {
        "Nothing malicious detected on $env:COMPUTERNAME" >> .\eif_results\_EIF-Log.txt
        }
    elseif($eif_cvrt -ne $null)
        {
        $eif_out = $eif_cvrt.Replace('Analysing', $newlinw +$newline + 'ComputerName: ' + $computer + $newline  + 'Analysing') | out-file .\eif_results\$env:COMPUTERNAME-EIF.txt
        }
    }


# Parameters received at the start of running the script
if($ComputerName -like '*.txt')
    {
    $cpu = Get-content $computername
    eif_call
    eif_retrieve
    }
elseif($ComputerName -eq 'localhost' -or $ComputerName -eq '127.0.0.1')
    {
    $eif_array = Invoke-Expression $EIF_Path
    eif_localhost
    }
elseif($ComputerName -notcontains '.txt')
    {
    $cpu = $ComputerName
    eif_call
    eif_retrieve
    }
else{Echo 'No IP or a file containing IPs were specified'}



