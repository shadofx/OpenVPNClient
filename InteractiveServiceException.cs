using System;

namespace OpenVPNClient
{
	public class InteractiveServiceException : Exception
	{
		public InteractiveServiceException(string errNum, string func, string msg) : base(GetMessage(errNum, func, msg))
		{
			this.ErrNum = errNum;
			this.Func = func;
			this.Msg = msg;
		}

		private static string GetMessage(string errNum, string func, string msg)
		{
			if (errNum.Equals("0x20000000")) errNum += "(ERROR_OPENVPN_STARTUP)";
			else if (errNum.Equals("0x20000001")) errNum += "(ERROR_STARTUP_DATA)";
			else if (errNum.Equals("0x20000002")) errNum += "(ERROR_MESSAGE_DATA)";
			else if (errNum.Equals("0x20000003")) errNum += "(ERROR_MESSAGE_TYPE)";
			return $"{errNum} : Function {func} : {msg}";
		}

		public string ErrNum { get; }
		public string Func { get; }
		public string Msg { get; }
	}

}
