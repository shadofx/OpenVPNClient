using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace OpenVPNClient
{
	public class Process
	{
		public static async Task<int> Start(string workingdir, string openvpnoptions, string stdin)
		{
			if (OperatingSystem.IsOSPlatform("windows"))
			{
				using var identity = WindowsIdentity.GetCurrent();
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
			else if (OperatingSystem.IsOSPlatform("linux"))
			{
				return await StartProcess("openvpn", workingdir, openvpnoptions, stdin);
			}
			throw new PlatformNotSupportedException();
		}
		private static async Task<int> StartProcess(string filename, string workingdir, string openvpnoptions, string stdin)
		{
			using var proc = new System.Diagnostics.Process();
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
