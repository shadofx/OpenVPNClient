using System.IO;
using System.Management.Automation;

namespace OpenVPNClient
{
	[Cmdlet(VerbsCommon.Get, "OpenVPN")]
	[OutputType(typeof(int))]
	[Alias("sovpn")]
	public class StartOpenVPNCommand:Cmdlet
	{
		[Parameter(Mandatory = false, HelpMessage = "Working directory for OpenVPN process, defaults to current directory")]
		public string WorkingDirectory { get; set; } = "";

		[Parameter(Mandatory = false, HelpMessage = "Command line arguments to pass to OpenVPN")]
		public string OpenVPNOptions { get; set; } = "";

		[Parameter(Mandatory = false, HelpMessage = "Input to send into started OpenVPN process")]
		public string StdIn { get; set; } = "";

		protected override void BeginProcessing()
		{
			if (string.IsNullOrEmpty(WorkingDirectory))
			{
				WorkingDirectory = Directory.GetCurrentDirectory();
				WriteDebug($"Using {WorkingDirectory} as WorkingDirectory since none is provided");
			}
			WriteObject(Process.Start(WorkingDirectory, OpenVPNOptions, StdIn).GetAwaiter().GetResult());
		}
	}
}
