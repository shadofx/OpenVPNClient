<#
.SYNOPSIS
Generates a Google Authenticator Token

.DESCRIPTION
Takes in a BASE32 encoded $Secret and generates an object with string Pin and int SecondsRemaining parameters

.PARAMETER Secret
BASE32 encoded Secret e.g. 5WYYADYB5DK2BIOV

.EXAMPLE
$token = Get-GoogleAuthenticatorPin -Secret 5WYYADYB5DK2BIOV
Write-Host "Token's PIN is" $token.Pin "with" $token.SecondsRemaining "seconds remaining"
.NOTES
Uses Otp.NET https://github.com/kspearrin/Otp.NET
#>
function Get-GoogleAuthenticatorPin{
	[CmdletBinding()]
	[OutputType([OpenVPNClient.GoogleAuthenticatorPin])]
	[Alias("ggap")]
	param (
		[Parameter(Mandatory=$true, Position=0, HelpMessage="BASE32 encoded Secret e.g. 5WYYADYB5DK2BIOV")]
		[String]
		$Secret
	)
	return [OpenVPNClient.GoogleAuthenticatorPin]::Get($Secret)
}
<#
.SYNOPSIS
Initates an instance of the openvpn process

.DESCRIPTION
Uses OpenVPNInteractiveService or admin permission to invoke a new openvpn process

.PARAMETER WorkingDirectory
Working directory for OpenVPN process, defaults to current directory

.PARAMETER OpenVPNOptions
Command line arguments to pass to OpenVPN

.PARAMETER StdIn
Input to send into started OpenVPN process. The LF (U000A) character can be used to simulate an enter key.

.EXAMPLE
An example

.NOTES
See https://community.openvpn.net/openvpn/wiki/OpenVPNInteractiveService
Also the OpenVPNClient.*.dll may be used .NET
#>
function Start-OpenVPN{
	[CmdletBinding()]
	[OutputType([int])]
	[Alias("sovpn")]
	param (
		[Parameter(Mandatory=$false,HelpMessage="Working directory for OpenVPN process, defaults to current directory")]
		[String]
		$WorkingDirectory = "",
		[Parameter(Mandatory=$false,HelpMessage="Command line arguments to pass to OpenVPN")]
		[String]
		$OpenVPNOptions = "",
		[Parameter(Mandatory=$false,HelpMessage="Input to send into started OpenVPN process")]
		[String]
		$StdIn = ""
	)
	if ([string]::IsNullOrEmpty($WorkingDirectory))
	{
		$WorkingDirectory = [System.IO.Directory]::GetCurrentDirectory();
		Write-Debug -Message "Using $WorkingDirectory as WorkingDirectory since none is provided"
	}
	return [OpenVpnClient.Process]::Start($WorkingDirectory, $OpenVPNOptions, $StdIn).GetAwaiter().GetResult()
}
<#
.SYNOPSIS
Adds Windows permissions to file

.DESCRIPTION
Long description

.PARAMETER SecretFile
File path to secure

.EXAMPLE
An example

.NOTES
General notes
#>
function SecureFile{
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$SecretFile
	)
	$sec = Get-Acl $SecretFile
	$sec.SetAccessRuleProtection($true, $false)
	$sec.RemoveAccessRuleAll((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")))
	$sec.RemoveAccessRuleAll((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")))
	$sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().User,"FullControl","Allow")))
	$sec | Set-Acl
}
function Connect-OpenVPN{
	[CmdletBinding(DefaultParameterSetName="Direct")]
	[OutputType([int])]
	[Alias("covpn")]
	param(
        [Parameter(Mandatory=$true,ParameterSetName="Direct")]
        [Parameter(Mandatory=$true,ParameterSetName="Recur")]
		[System.IO.FileInfo]
		$Config,
        [Parameter(Mandatory=$false,ParameterSetName="Direct")]
		[pscredential]
		$Credential,
		[Parameter(Mandatory=$false,ParameterSetName="Recur")]
		[System.IO.FileInfo]
		$CredentialFile,
		[Parameter(Mandatory=$false,ParameterSetName="Recur")]
		[System.IO.FileInfo]
		$SecretFile,
		[Parameter(Mandatory=$false,ParameterSetName="Recur")]
		[switch]
		$IgnoreUserDomain
	)
	if($PsCmdlet.ParameterSetName -eq "Direct"){
		Write-Debug "Connecting OpenVPN with $Config for user $($Credential.UserName)"
		$openConnectionsLocation = New-Item -Path "$env:USERPROFILE/OpenVPN/OpenConnections" -ItemType Directory -Force
		$results = $openConnectionsLocation|Get-ChildItem -Directory|ForEach-Object{
			$openConnectionItem = $_
			$removePath = $false
			$pidpath ="$($openConnectionItem.FullName)/pid.txt"
			Write-Debug "Checking $($openConnectionItem.FullName)"
			if(Test-Path $pidpath)
			{
				$processid = [int]::Parse((Get-Content $pidpath -Raw))
				Write-Debug "PID $processid detected at $pidpath"
				$proc = Get-Process -Id $processid -ErrorAction Ignore
				if(!$proc -or $proc.HasExited -or $proc.ProcessName -ne 'openvpn'){
					Write-Debug "PID $processid is dead and should be removed"
					$removePath = $true
				}else{
					Write-Debug "PID $processid is alive"
					$openConnectionItem | Get-ChildItem -File -Filter '*.ovpn'|ForEach-Object {
						Write-Debug "Checking OVPN $_"
						if($Config.Name -eq $_.Name){
							Wait-OpenConnectionReady -OpenConnectionDirectory $openConnectionItem
							$processid
						}
					}
				}
			}
			else{
				$removePath = $true
			}
			if($removePath){$openConnectionItem|Remove-Item -Recurse -Force}
		}
		if($results){
			Write-Debug "In-progress connection detected $results"
			return $results
		}else{
			$guid = New-Guid
			$newconfigpath = New-Item -Path "$($openConnectionsLocation.FullName)/$guid" -ItemType Directory -Force
			$newconfigfile = New-Item -Path "$($newconfigpath.FullName)/$($Config.Name)" -ItemType File -Force
			Write-Debug "Initializing connection $($newconfigpath.FullName)"
			$configcontent = Get-Content $Config -Raw
			if($Credential){
				$configcontent = $configcontent.Replace("auth-user-pass", "auth-user-pass auth.$guid.txt")
			}
			Set-Content -Value $configcontent -Path $newconfigfile -NoNewline
			$options = "--config `"$newconfigfile`" --log `"$($newconfigpath.FullName)/out.log`" --writepid `"$($newconfigpath.FullName)/pid.txt`""
			if($Credential){
				Write-Debug "Attaching $($Credential.UserName) credential to $($newconfigpath.FullName)"
				$secretfile = New-Item -Path "$($newconfigpath.FullName)/auth.$guid.txt" -ItemType File -Force
				$username = $Credential.UserName
				$password = [System.Net.NetworkCredential]::new("", $Credential.Password).Password
				@($username,$password)|Set-Content $secretfile
				$result = Start-OpenVPN -WorkingDirectory $newconfigpath -OpenVPNOptions $options -StdIn "$username`n$password`n"	
			}else{
				Write-Debug "No credential for $newconfigpath"
				$result = Start-OpenVPN -WorkingDirectory $newconfigpath -OpenVPNOptions $options -StdIn ""	
			}
			Wait-OpenConnectionReady -OpenConnectionDirectory $newconfigpath
			if(!$Credential){
				$secretfile | Remove-Item -Force
			}
			Write-Debug "Started process $result"
			return $result
		}
	}
	elseif($PsCmdlet.ParameterSetName -eq "Recur"){
		$askForCredentials = !$CredentialFile.Exists
		$connected = $false
		do{
			Write-Debug "Attempting VPN connection"
			$rawcredential = if($askForCredentials){
				$askmsg = "Enter Credential for $CredentialFile"
				if($username){
					Get-Credential -UserName $username -Message $askmsg
				}else{
					Get-Credential -Message $askmsg
				}
				$credentialInputted = $true
			}else{
				Write-Debug "Importing credentials from $CredentialFile"
				Import-Clixml -Path $CredentialFile
				$credentialInputted = $false
			}
			if(!$rawcredential){
				throw "No credential provided"
			}
			$username = $rawcredential.UserName
			$askForCredentials = $false
			$credential = $rawcredential
			if($SecretFile){
				if($SecretFile.Exists){
					Write-Debug "Importing secret from $SecretFile"
					$secret = Import-Clixml -Path $SecretFile
				}else{
					$secret = Read-Host -AsSecureString -Prompt "Enter secret for $SecretFile"
					Export-Clixml -Path $SecretFile -InputObject $secret
					SecureFile -SecretFile $SecretFile
					Write-Verbose "Exported secret to $SecretFile"
					$SecretFile.Refresh()
				}
				Write-Debug "Attaching Google Token to $($credential.UserName)"
				$credential = $credential | Add-GoogleTokenToCredential -Secret $secret
			}
			if($IgnoreUserDomain -and $IgnoreUserDomain.IsPresent){
				Write-Debug "Removing Domain from $($credential.UserName)"
				$credential = $credential | Remove-DomainFromCredential
			}
			try{
				$result = Connect-OpenVPN -Config $Config -Credential $credential
				$connected = $true
				Write-Debug "Successfully connected OpenVPN with $Config for user $($credential.UserName)"
				if($credentialInputted){
					Export-Clixml -Path $CredentialFile -InputObject $rawcredential
					SecureFile -SecretFile $CredentialFile
					Write-Verbose "Exported $($rawcredential.UserName) credential to $CredentialFile"
					$CredentialFile.Refresh()
				}
			}catch{
				if($_.Exception.Message -eq "Invalid Username or Password (AUTH: Received control message: AUTH_FAILED)"){
					Write-Warning $_
					$askForCredentials = $true
				}
				else{
					throw $_
				}
			}
		}while(!$connected)
		return $result
	}
}
<#
.SYNOPSIS
Pauses until a directory being used by openvpn indicates connectivity

.DESCRIPTION
Pauses until certain key phrases inside the log file for a directory being used by openvpn indicates successful connection, or fatal error

.PARAMETER OpenConnectionDirectory
Directory containing out.log file associated with active openvpn connection

.EXAMPLE
An example

.NOTES
Not to be used without Connect-OpenVpn
#>
function Wait-OpenConnectionReady{
	[CmdletBinding()]
	[OutputType([void])]
	param(
		[System.IO.DirectoryInfo]
		$OpenConnectionDirectory
	)
	$result = ""
	do{
		Write-Debug "Waiting for Connection $OpenConnectionDirectory"
		Start-Sleep -Milliseconds 2000
		$file = $OpenConnectionDirectory|Get-ChildItem -File -Filter 'out.log' -ErrorAction Continue
		if($file){
			Write-Debug "Copying $file for check"
			$file2 = $file|Copy-Item -Destination "$($OpenConnectionDirectory.FullName)/out.$(New-Guid).log" -Force -PassThru
			$content = Get-Content $file2 -Raw
			if($content.Contains("AUTH: Received control message: AUTH_FAILED")){
				$result = "Invalid Username or Password (AUTH: Received control message: AUTH_FAILED)"
			}
			elseif($content.Contains("Initialization Sequence Completed With Errors ( see http://openvpn.net/faq.html#dhcpclientserv )")){
				$result = "TCP/IP stack is corrupted (see http://openvpn.net/faq.html#dhcpclientserv)"
			}
			elseif($content.Contains("Initialization Sequence Completed")){
				$result = "Success"
			}
			elseif($content.Contains("Exiting due to fatal error")){
				$result = "Exiting due to fatal error : check $file for details"
			}
			$file2|Remove-Item
		}
		else{
			Write-Debug "$file not found"
		}
	}while($result -eq "")
	if($result -ne "Success"){
		throw $result
	}
}
function Add-GoogleTokenToCredential{
	[CmdletBinding()]
	[OutputType([pscredential])]
	[Alias("agttc")]
	param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[pscredential]
		$Credential,
		[Parameter(Mandatory=$true)]
		[securestring]
		$Secret
	)
	$textSecret = [System.Net.NetworkCredential]::new("", $Secret).Password
	$pin = Get-GoogleAuthenticatorPin -Secret $textSecret
	$newpw = $Credential.Password.Copy()
	$pin.Pin.ToCharArray()|ForEach-Object{$newpw.AppendChar($_)}
	return [pscredential]::new($Credential.UserName,$newpw)
}
function Remove-DomainFromCredential{
	[CmdletBinding()]
	[OutputType([pscredential])]
	[Alias("rdfc")]
	param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[pscredential]
		$Credential
	)
	if($Credential.UserName.Contains('\')){
		$res = $Credential.UserName.Split('\')
		$res2 = [string[]]::new($res.Count-1)
		for($i = 1;$i -lt $res.Count;$i++){
			$res2[$i-1] = $res[$i]
		}
		$resname = [string]::Join('\',$res2)
	}
	else{
		Write-Debug "No Domain found in credential username $($Credential.UserName)"
		return $Credential
	}
	return [pscredential]::new($resname,$Credential.Password)
}
function Connect-OpenVpnGUI{
    param(
        [Parameter(Mandatory=$true)]
        [string]$Connect,
        [string]$LoginInfoPath,
        [string]$SecretPath,
        [string]$OpenVpnGuiPath = 'C:\Program Files\OpenVPN\bin\openvpn-gui.exe',
        [switch]$RequeryLoginInfo,
        [switch]$RequerySecret,
        [switch]$IgnoreUserDomain
    )
    $manager = [pscustomobject]@{
        Connect = $Connect
        LogPath = "$env:USERPROFILE\OpenVPN\log\$Connect.log"
        OVPNPath = "$env:USERPROFILE\openvpn\config\$Connect\$Connect.ovpn"
        BackupPath = "$env:USERPROFILE\openvpn\config\$Connect\$Connect.ovpn.bak"
        OVPNAuthPath = "$env:USERPROFILE\openvpn\config\$Connect\auth.txt"
        OpenVpnGuiPath = $OpenVpnGuiPath
        IgnoreUserDomain = $IgnoreUserDomain.IsPresent
    }
    $manager | Add-Member -MemberType ScriptMethod -Name PromptChoice -Value {
        param([string]$message)
        $options = [System.Management.Automation.Host.ChoiceDescription[]](
            (New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes."),
            (New-Object System.Management.Automation.Host.ChoiceDescription "&No","No."), 
            (New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel","Cancel."))
        switch ($host.UI.PromptForChoice("", $message, $options, 1)) {
            0{"Yes"}
            1{"No"}
            2{"Cancel"}
        }
    }
    $manager | Add-Member -MemberType ScriptProperty -Name LogState -Value {
        $log = Get-Content -Path $this.LogPath -ErrorAction Ignore|Select-String "MANAGEMENT: >STATE:"|Select-Object -Last 1
        if($log){$log}
        else{""}
    }
    $manager | Add-Member -MemberType ScriptProperty -Name IsConnected -Value {
        return (Get-Process openvpn -ErrorAction Ignore) -and ($this.LogState|Select-String "CONNECTED,SUCCESS")
    }
    if($manager.IsConnected){
        Write-Verbose "$Connect is already connected"
        return $true
    }elseif(!(Test-Path $manager.OVPNPath)){
        Write-Warning "$($manager.OVPNPath) does not exist"
        return $false
    }else{
        if($LoginInfoPath){
            $manager|Add-Member -MemberType NoteProperty -Name LoginInfo -Value $null
            $manager|Add-Member -MemberType NoteProperty -Name LoginInfoPath -Value $LoginInfoPath
            $manager|Add-Member -MemberType ScriptMethod -Name QueryLoginInfo -Value{
                if($this.LoginInfo){
                    $this.LoginInfo = Get-Credential -Message "Input credentials for $($this.LoginInfoPath)" -UserName $this.LoginInfo.UserName
                }else{
                    $this.LoginInfo = Get-Credential -Message "Input credentials for $($this.LoginInfoPath)"
                }
            }
            $manager|Add-Member -MemberType ScriptMethod -Name SaveLoginInfo -Value{
                $dosave = $true
                if(Test-Path $this.LoginInfoPath){
                    $temp = Import-Clixml -Path $this.LoginInfoPath
                    if(($temp.UserName -eq $this.LoginInfo.UserName) -and ($temp.GetNetworkCredential().Password -eq $this.LoginInfo.GetNetworkCredential().Password)){
                        $dosave = $false
                    }
                }
                if($dosave){
                    $this.LoginInfo | Export-Clixml -Path $this.LoginInfoPath
                }
            }
            $manager|Add-Member -MemberType ScriptMethod -Name LoadLoginInfo -Value{
                $this.LoginInfo = Import-Clixml -Path $this.LoginInfoPath
            }
            if(!(Test-Path $manager.LoginInfoPath)){
                $manager.QueryLoginInfo()
                $manager.SaveLoginInfo()
            }elseif($RequeryLoginInfo.IsPresent){
                $manager.QueryLoginInfo()
            }else{
                $manager.LoadLoginInfo()
            }
            if($SecretPath){
                $manager|Add-Member -MemberType NoteProperty -Name Secret -Value $null
                $manager|Add-Member -MemberType NoteProperty -Name SecretPath -Value $SecretPath
                $manager|Add-Member -MemberType ScriptMethod -Name QuerySecret -Value{
                    $this.Secret = Read-Host -Prompt "Enter secret for $($this.SecretPath)" -AsSecureString
                }
                $manager|Add-Member -MemberType ScriptMethod -Name SaveSecret -Value{
                    $this.Secret | Export-Clixml -Path $this.SecretPath
                }
                $manager|Add-Member -MemberType ScriptMethod -Name LoadSecret -Value{
                    $this.Secret = Import-Clixml -Path $this.SecretPath
                }
                if(!(Test-Path $manager.SecretPath)){
                    $manager.QuerySecret()
                    $manager.SaveSecret()
                }elseif($RequerySecret.IsPresent){
                    $manager.QuerySecret()
                }else{
                    $manager.LoadSecret()
                }
                $manager|Add-Member -MemberType ScriptProperty -Name Password -Value{
                    $pass = $this.LoginInfo.GetNetworkCredential().Password
                    $pin = Get-GoogleAuthenticatorPin -Secret $this.Secret
                    return $pass + $pin.Pin
                }
                $manager|Add-Member -MemberType ScriptMethod -Name OnSuccess -Value{
                    $this.SaveLoginInfo()
                    $this.SaveSecret()
                }
                $manager|Add-Member -MemberType ScriptMethod -Name GetRetryOnAuthFailure -Value{
                    $requeryLoginInfos = $this.PromptChoice("Requery Credentials?")
                    if($requeryLoginInfos -eq "Cancel"){
                        return $false
                    }else{
                        switch($this.PromptChoice("Requery Secret?")){
                            "Yes"{
                                if($requeryLoginInfos -eq "Yes"){
                                    $this.QueryLoginInfo()
                                    $this.QuerySecret()
                                    return $true
                                }else{
                                    $this.QuerySecret()
                                    return $true
                                }
                            }
                            "No"{
                                if($requeryLoginInfos -eq "Yes"){
                                    $this.QueryLoginInfo()
                                    return $true
                                }else{
                                    return $false
                                }
                            }
                            "Cancel"{
                                return $false
                            }
                        }
                    }
                }
            }else{
                $manager|Add-Member -MemberType ScriptProperty -Name Password -Value{
                    return $this.LoginInfo.GetNetworkCredential().Password
                }
                $manager|Add-Member -MemberType ScriptMethod -Name OnSuccess -Value{
                    $this.SaveLoginInfo()
                }
                $manager|Add-Member -MemberType ScriptMethod -Name GetRetryOnAuthFailure -Value{
                    switch($this.PromptChoice("Requery Credentials?")){
                        "Yes"{
                            $this.QueryLoginInfo()
                            return $true
                        }
                        "No"{
                            return $false
                        }
                        "Cancel"{
                            return $false
                        }
                    }
                }
            }
            $manager|Add-Member -MemberType ScriptProperty -Name UserName -Value{
                $username = $this.LoginInfo.UserName
                if($this.IgnoreUserDomain){
                    $username = Split-Path -Leaf $username
                }
                return $username
            }
            $manager|Add-Member -MemberType ScriptMethod -Name GetConnection -Value{
                if(Test-Path $this.BackupPath){
                    Remove-Item -Path $this.OVPNPath
                    Copy-Item -Path $this.BackupPath -Destination $this.OVPNPath
                }else{
                    Copy-Item -Path $this.OVPNPath -Destination $this.BackupPath
                }
                $content = Get-Content -Path $this.BackupPath -Raw
                $content = [regex]::Replace($content,"auth-user-pass([ \t]+[^\r\n]+)?([\r\n]+)","remap-usr1 SIGTERM`nkeepalive 10 120`ninactive 0`nauth-user-pass auth.txt`$2")
                Set-Content -Path $this.OVPNPath -Value $content -NoNewline
                $result = ''
                while(!$result){
                    Set-Content -Path $this.OVPNAuthPath -Value "$($this.UserName)`n$($this.Password)"
                    Set-Content -Path $this.LogPath -Value ""
                    &($this.OpenVpnGuiPath) --connect "$($this.Connect)"
                    while(!$result){
                        Start-Sleep 1
                        $state = $this.LogState
                        if($state|Select-String ",CONNECTED,SUCCESS,"){
                            $result = "Connected"
                        }elseif($currentstatus|Select-String ",EXITING,auth-failure,"){
                            $result = "AuthFailure"
                        }elseif($state|Select-String ",EXITING,"){
                            $result = $state
                        }else{
                            Write-Progress -Activity "Connecting to $Connect" -Status "$state"
                        }
                    }
                    Write-Progress -Activity "Connecting to $Connect" -Completed
                    if($result -eq "AuthFailure" -and $this.GetRetryOnAuthFailure()){
                        $result = ""
                    }
                }
                Remove-Item -Path $this.OVPNAuthPath
                if(Test-Path $this.BackupPath){
                    Remove-Item -Path $this.OVPNPath
                    Copy-Item -Path $this.BackupPath -Destination $this.OVPNPath
                    Remove-Item -Path $this.BackupPath
                }
                if($result -eq "Connected"){
                    $this.OnSuccess()
                    return $true
                }elseif($result -eq "AuthFailure"){
                    Write-Warning "Authentication Failure for $($this.Connect)"
                    return $false
                }else{
                    Write-Warning $result
                    return $false
                }
            }
        }else{
            $manager|Add-Member -MemberType ScriptMethod -Name GetConnection -Value{
                Set-Content -Path $this.LogPath -Value ""
                &($this.OpenVpnGuiPath) --connect "$($this.Connect)"
                $done = $false
                while(!$done){
                    Start-Sleep 1
                    $state = $this.LogState
                    if($state|Select-String ",CONNECTED,SUCCESS,"){
                        $done = $true
                        return $true
                    }elseif($state|Select-String ",EXITING,"){
                        $done = $true
                        Write-Warning $state
                    }else{
                        Write-Progress -Activity "Connecting to $Connect" -Status "$state"
                    }
                }
                Write-Progress -Activity "Connecting to $Connect" -Completed
            }
        }

    }
    return $manager.GetConnection()
}
Export-ModuleMember -Function Get-GoogleAuthenticatorPin -Alias ggap
Export-ModuleMember -Function Start-OpenVPN -Alias sovpn
Export-ModuleMember -Function Connect-OpenVPN -Alias covpn
Export-ModuleMember -Function Add-GoogleTokenToCredential -Alias agttc
Export-ModuleMember -Function Remove-DomainFromCredential -Alias rdfc
Export-ModuleMember -Function Connect-OpenVpnGUI -Alias covg