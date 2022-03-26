using OtpNet;

namespace OpenVPNClient
{
	public class GoogleAuthenticatorPin
	{
		public static GoogleAuthenticatorPin Get(string secret)
		{

			var bytes = Base32Encoding.ToBytes(secret);

			var totp = new Totp(bytes);

			var result = totp.ComputeTotp();
			var remainingTime = totp.RemainingSeconds();
			return new GoogleAuthenticatorPin(result, remainingTime);
		}

		public string Pin { get; }
		public int SecondsRemaining { get; }

		public GoogleAuthenticatorPin(string pin, int secondsRemaining)
		{
			Pin = pin;
			SecondsRemaining = secondsRemaining;
		}
	}
}
