using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

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
