using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;

namespace OpenVPNClient
{
	public class Module : IModuleAssemblyInitializer
	{
		void IModuleAssemblyInitializer.OnImport()
		{

		}
		public static string DecodeSecret(SecureString secret)
		{
			return Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(secret));
		}
	}
}
