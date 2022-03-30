[![Gallery](https://img.shields.io/powershellgallery/v/OpenVPNClient?label=PS%20Gallery&logo=powershell&logoColor=white)](https://www.powershellgallery.com/packages/OpenVPNClient)
# OpenVPNClient
Streamlines use of OpenVPN from powershell from non-Admin terminals

`Start-OpenVpn` calls a locally installed [OpenVPNInteractive Service](https://community.openvpn.net/openvpn/wiki/OpenVPNInteractiveService) to start an instance of OpenVPN.

`Connect-OpenVpn` tracks active connections by OVPN file and PID, and allows for appending a Google Authenticator token to the end of the password.
