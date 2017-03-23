# EIF_Parser
Evil Inject Finder Remote Capability and Parser

# About
EIF_Parser.ps1 provides the following capability:
- Executes Evil Inject Finder (EIF) on a remote system or systems
- Retrieves the data gathered by EIF on remote systems
- On the local system, presents only the processes with 'yes' in the MZ or DOS column
- Logs systems not accessible, for one reason or another

# Requirements
- Evil Inject Finder (EIF) (https://github.com/psmitty7373/eif)
- PowerShell v2 or above
- RunAs Administrator
- WMI
- C$

# Examples
Running EvilInjectFinder on the specified IPs in computers.txt 
    
    PS C:\> .\eif_parser.ps1 -ComputerName c:\users\blue\desktop\computers.txt -EIF_Path "C:\users\blue\desktop\evilinjectfinder.exe"

Running EvilInjectFinder on a specific IP.
    
    PS C:\> .\eif_parser.ps1 -ComputerName 192.168.10.26 -EIF_Path "C:\users\blue\desktop\evilinjectfinder.exe"

Running EvilInjectFinder on the local machine.
    
    PS C:\> .\eif_parser.ps1 -ComputerName 127.0.0.1 -EIF_Path "C:\users\blue\desktop\evilinjectfinder.exe"


# Credits
Huge thanks to @psmitty7373 for developing Evil Inject Finder.
