[![Gallery](https://img.shields.io/powershellgallery/v/OpenVPNClient?label=PS%20Gallery&logo=powershell&logoColor=white)](https://www.powershellgallery.com/packages/OpenVPNClient)
# OpenVPNClient
Streamlines use of OpenVPN from powershell from non-Admin terminals

`Start-OpenVpn` calls a locally installed [OpenVPNInteractive Service](https://community.openvpn.net/openvpn/wiki/OpenVPNInteractiveService) to start an instance of OpenVPN.

`Connect-OpenVpn` tracks active connections by OVPN file and PID, and allows for appending a Google Authenticator token to the end of the password.

Running the following would prompt for your credentials and Google Authenticator secret and store them in your user profile folder for later, and return the process ID of a relevant openvpn process, either newly created or from an active connection
```powershell
Install-Module -Name OpenVPNClient -Scope CurrentUser -Force
Connect-OpenVpn -Config "$env:USERPROFILE\openvpn\config\myConfigurationFile\myConfigurationFile.ovpn" `
    -CredentialFile "$env:USERPROFILE\my.credential" -SecretFile "$env:USERPROFILE\my.secret" 
```