
function Enable-Rdp-With-Security{
    <#
    .SYNOPSIS
        Enable RDP connection
    .DESCRIPTION
        Enable RDP connection with all security options
    #>
    param (
        [string] $ComputerName,
        [string] $UserName
    )
    Import-Module -Name PolicyFileEditor

    # Step-1 Enable RDP with NLA option 
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
    (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $ComputerName -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)
    # Step-2 Add Users
    if(((Get-LocalGroupMember -Group "Remote Desktop Users").Name  -contains "$ComputerName\$UserName") -eq $false){
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member "$ComputerName\$UserName"
    }

   # Step 3- Add users in Users Right Assignment - Local Policies
   Replace-SecurityTest -Usernames "Administrators" -SecuritySetting "SeRemoteInteractiveLogonRight" -SaveFile "C:\Config22.cfg"
#    Step 4: Local Group Policy Editor
    
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |   ForEach-Object { 
        if (-not (Test-Path $_)) {
            New-Item -path $_ -force
        }
    }
    $MachineDir = "$env:windir\system32\GroupPolicy\Machine\registry.pol"

    Set-PolicyFileEntry -Path $MachineDir -Key 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'MinEncryptionLevel' -Data 3 -Type 'DWord'
    Set-PolicyFileEntry -Path $MachineDir -Key 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'fEncryptRPCTraffic' -Data 1 -Type 'DWord'
    Set-PolicyFileEntry -Path $MachineDir -Key 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'UserAuthentication' -Data 1 -Type 'DWord'
    Set-PolicyFileEntry -Path $MachineDir -Key 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'SecurityLayer' -Data 2 -Type 'DWord'
  
    GpUpdate
    # Step 5: Port Number Change
    
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" |   ForEach-Object { 
        if (-not (Test-Path $_)) {
            New-Item -path $_ -force
        }
    }

    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'-name "PortNumber" -Value 665
    New-NetFirewallRule -DisplayName "Allow Port" -Direction Inbound -LocalPort 665 -Protocol TCP -Action Allow
}
function Replace-SecurityTest([string[]]$Usernames,[string]$SecuritySetting, $SaveFile = "C:\Configuration.cfg"){
    function Get-SID($USER){
        $objUser = New-Object System.Security.Principal.NTAccount("$USER")
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        $strSID.Value
    }
    secedit /export /cfg $SaveFile
    $reader = [System.IO.File]::OpenText($SaveFile)
    while($null -ne ($line = $reader.ReadLine())) {
        if ($line -like "*$SecuritySetting*"){
            $reader.Close()
            Write-Host $line
            $line2 = $line.Remove($line.IndexOf("="))
            Write-Host $line2
            $line2 += "= "
            foreach($user in $Usernames){
                $line2 += "*$(Get-SID -USER "$user"), "
            }
            $line2 = $line2.Remove($line2.LastIndexOf(", "))
            (gc $SaveFile).replace("$Line", "$Line2") | Out-File $SaveFile
            secedit /configure /db c:\windows\security\local.sdb /cfg $SaveFile /areas USER_RIGHTS
            
            rm -force $SaveFile -confirm:$false
            break
        }
    }
}
Enable-Rdp-With-Security -ComputerName "Computer Name" -UserName "User Name"