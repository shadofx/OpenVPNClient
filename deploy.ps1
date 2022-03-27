Remove-Item "$PSScriptRoot/bin" -Recurse -ErrorAction Continue
dotnet build "$PSScriptRoot/OpenVPNClient.sln"
$modules = ($env:PSModulePath).Split(';')[0]
$moduleinfo = Invoke-Expression (Get-Content .\OpenVPNClient.psd1 -Raw)
Remove-Item "$modules/OpenVPNClient" -Recurse -ErrorAction Continue
New-Item "$modules/OpenVPNClient/$($moduleinfo.ModuleVersion)" -ItemType Directory -Force
Copy-Item "$PSScriptRoot/bin/OpenVPNClient/*" "$modules/OpenVPNClient/$($moduleinfo.ModuleVersion)" -Recurse -Verbose -Force
$secretPath = "$env:USERPROFILE/psgallery api key.secret"
if(Test-Path $secretPath){
	$secret = Import-Clixml -Path $secretPath
	$key = [System.Net.NetworkCredential]::new("", $secret).Password
}else{
	$key = Read-Host -Prompt "Enter psgallery api key "
	$secret = ConvertTo-SecureString -String $key -AsPlainText -Force
	Export-Clixml -Path $secretPath -InputObject $secret
	$sec = Get-Acl $secretPath
	$sec.SetAccessRuleProtection($true, $false)
	$sec.RemoveAccessRuleAll((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")))
	$sec.RemoveAccessRuleAll((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")))
	$sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().User,"FullControl","Allow")))
	$sec | Set-Acl
}
Publish-Module -Name OpenVPNClient -NuGetApiKey $key -Verbose -RequiredVersion $moduleinfo.ModuleVersion