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
		[Parameter(HelpMessage="Working directory for OpenVPN process, defaults to current directory")]
		[String]
		$WorkingDirectory = "",
		[Parameter(HelpMessage="Command line arguments to pass to OpenVPN")]
		[String]
		$OpenVPNOptions = "",
		[Parameter(HelpMessage="Input to send into started OpenVPN process")]
		[String]
		$StdIn = ""
	)
	if ([string]::IsNullOrEmpty($WorkingDirectory))
	{
		$WorkingDirectory = [System.IO.directory]::GetCurrentDirectory();
		Write-Debug -Message "Using $WorkingDirectory as WorkingDirectory since none is provided"
	}
	return [OpenVpnClient.Process]::Start($WorkingDirectory, $OpenVPNOptions, $StdIn).GetAwaiter().GetResult()
}
function Connect-OpenVPN{
	[CmdletBinding()]
	[OutputType([int])]
	[Alias("covpn")]
	param(
		[ValidateScript({$_ -is [string] -or $_ -is [System.IO.FileInfo]})]
		[object]
		$Config,
		[pscredential]
		$Credential
	)
	if($Config -is [string]){$Config = Get-Item $Config}
	$openConnectionsLocation = New-Item -Path "$env:USERPROFILE/OpenVPN/OpenConnections" -ItemType Directory -Force
	$results = Get-ChildItem $openConnectionsLocation -Directory|ForEach-Object{
		$openConnectionItem = $_
		$removePath = $false
		$processid = [int]::Parse((Get-Content "$openConnectionItem/pid.txt" -Raw))
		if((Get-Process -Id $processid).HasExited){
			$removePath = $true
		}else{
			Get-ChildItem $openConnectionItem -File -Filter '*.ovpn'|ForEach-Object {
				if($Config.Name -eq $openConnectionItem.Name){
					Wait-OpenConnectionReady -OpenConnectionDirectory $openConnectionItem
					$processid
				}
			}
		}
		if($removePath){Remove-Item $openConnectionItem -Recurse -Force}
	}
	if($results){
		return $results
	}else{
		$guid = New-Guid
		$newconfigpath = New-Item -Path "$openConnectionsLocation/$guid" -ItemType Directory -Force
		$newconfigfile = New-Item -Path "$newconfigpath/$($Config.Name)" -ItemType File -Force
		$configcontent = Get-Content $Config -Raw
		$configcontent = $configcontent.Replace("auth-user-pass", "auth-user-pass auth.$guid.txt")
		Set-Content -Value $configcontent -Path $newconfigfile -NoNewline
		$secretfile = New-Item -Path "$newconfigpath/auth.$guid.txt" -ItemType File -Force
		$username = $Credential.UserName
		$password = [System.Net.NetworkCredential]::new("", $Credential.Password).Password
		@($username,$password)|Set-Content $secretfile
		$result = Start-OpenVPN -WorkingDirectory $newconfigpath `
			-OpenVPNOptions "--config `"$newconfigfile`" --log `"$newconfigpath/out.log`" --writepid `"$newconfigpath/pid.txt`"" `
			-StdIn "$username`n$password`n"	
		Wait-OpenConnectionReady -OpenConnectionDirectory $newconfigpath
		Remove-Item $secretfile -Force
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
	$file = Get-ChildItem $_ -File -Filter 'out.log'
	do{
		Start-Sleep -Milliseconds 500
		$file2 = Copy-Item $file -Destination "$OpenConnectionDirectory/out.$(New-Guid).log" -Force
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
		Remove-Item $file2
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
		[pscredential]
		$Credential,
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
		[pscredential]
		$Credential
	)
	if($Credential.UserName.Contains('\')){

	}
	else{
		Write-Debug "No Domain found in credential username $($Credential.UserName)"
		return $Credential
	}
	return [pscredential]::new($Credential.UserName,$Credential.Password)
}

Export-ModuleMember -Function Get-GoogleAuthenticatorPin -Alias ggap
Export-ModuleMember -Function Start-OpenVPN -Alias sovpn
Export-ModuleMember -Function Connect-OpenVPN -Alias covpn
Export-ModuleMember -Function Add-GoogleTokenToCredential -Alias agttc
Export-ModuleMember -Function Remove-DomainFromCredential -Alias rdfc