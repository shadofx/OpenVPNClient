using System;
#if !NETFRAMEWORK
using System.Runtime.Versioning;
#endif
using System.Security.Principal;
using System.Threading.Tasks;

namespace OpenVPNClient
{
	public class Process
	{
		public static async Task<int> Start(string workingdir, string openvpnoptions, string stdin)
		{
#if !NETFRAMEWORK
			if (OperatingSystem.IsOSPlatform("windows"))
			{
				return await StartOnWindows(workingdir, openvpnoptions, stdin);
			}
			else if (OperatingSystem.IsOSPlatform("linux"))
			{
				return await StartProcess("openvpn", workingdir, openvpnoptions, stdin);
			}
			throw new PlatformNotSupportedException();
#else
			return await StartOnWindows(workingdir, openvpnoptions, stdin);
#endif
		}

#if !NETFRAMEWORK
		[SupportedOSPlatform("windows")]
#endif
		private static async Task<int> StartOnWindows(string workingdir, string openvpnoptions, string stdin)
		{
			using (var identity = WindowsIdentity.GetCurrent())
			{
				var principal = new WindowsPrincipal(identity);
				if (principal.IsInRole(WindowsBuiltInRole.Administrator))
				{
					return await StartProcess($"{Environment.GetEnvironmentVariable("ProgramFiles")}\\OpenVpn\\bin\\openvpn.exe"
						, workingdir, openvpnoptions, stdin);
				}
				else
				{
					return await InteractiveService.Call(@"\\.\pipe\openvpn\service", workingdir, openvpnoptions, stdin);
				}
			}
		}

		private static async Task<int> StartProcess(string filename, string workingdir, string openvpnoptions, string stdin)
		{
			using (var proc = new System.Diagnostics.Process())
			{
				proc.StartInfo.FileName = filename;
				proc.StartInfo.Arguments = openvpnoptions;
				proc.StartInfo.WorkingDirectory = workingdir;
				proc.StartInfo.RedirectStandardInput = true;
				proc.StartInfo.RedirectStandardOutput = true;
				proc.Start();
				await proc.StandardInput.WriteLineAsync(stdin);
				return proc.Id;
			}
		}
	}
}
