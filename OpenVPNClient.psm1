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
Export-ModuleMember -Function Get-GoogleAuthenticatorPin -Alias ggap
Export-ModuleMember -Function Start-OpenVPN -Alias sovpn