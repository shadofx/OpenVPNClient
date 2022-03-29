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
					Export-Clixml -Path $SecretFile -OutVariable $secret
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

Export-ModuleMember -Function Get-GoogleAuthenticatorPin -Alias ggap
Export-ModuleMember -Function Start-OpenVPN -Alias sovpn
Export-ModuleMember -Function Connect-OpenVPN -Alias covpn
Export-ModuleMember -Function Add-GoogleTokenToCredential -Alias agttc
Export-ModuleMember -Function Remove-DomainFromCredential -Alias rdfc