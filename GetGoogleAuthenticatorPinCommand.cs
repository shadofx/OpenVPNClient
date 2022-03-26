using System.Management.Automation;

namespace OpenVPNClient
{
	[Cmdlet(VerbsCommon.Get, "GoogleAuthenticatorPin")]
	[OutputType("VPNTools.GoogleAuthenticator.GoogleAuthenticatorPin")]
	[Alias("ggap")]
	public class GetGoogleAuthenticatorPinCommand : PSCmdlet
	{

		[Parameter(Mandatory = true, Position = 0, HelpMessage = "BASE32 encoded Secret e.g. 5WYYADYB5DK2BIOV", ParameterSetName = "Secure")]
		[Alias("s")]
		public string Secret { get; set; }

		protected override void BeginProcessing()
		{
			WriteObject(GoogleAuthenticatorPin.Get(Secret));
		}
	}
}
