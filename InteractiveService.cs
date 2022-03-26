using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System;
using System.IO;
using System.Threading;

namespace OpenVPNClient
{
	[SupportedOSPlatform("windows")]
	public static class InteractiveService
	{
		public static async Task<int> Call(string pipeName, string workingdir, string openvpnoptions, string stdin, int readBufferSize = 1024, CancellationToken cancellationToken = default(CancellationToken))
		{
			var msgbytes = Encoding.Unicode.GetBytes($"{workingdir}\0{openvpnoptions}\0{stdin}\0");//construct message and convert to byte array
			var writebuffer = Marshal.AllocHGlobal(msgbytes.Length);
			FromByteBuffer(msgbytes, ref writebuffer, msgbytes.Length);
			var writebufferlength = msgbytes.Length;
			var readbuffer = Marshal.AllocHGlobal(readBufferSize);
			var pipe_readmode_message = Marshal.AllocHGlobal(4);
			Marshal.WriteInt32(pipe_readmode_message, unchecked((int)Native.PIPE_READMODE_MESSAGE));
			var pipeHandle = Native.CreateFile(pipeName,
				Native.GENERIC_READ | Native.GENERIC_WRITE,
				0,
				IntPtr.Zero,
				FileMode.Open,
				Native.FILE_FLAG_OVERLAPPED,
				IntPtr.Zero);
			try
			{
				if (!Native.SetNamedPipeHandleState(pipeHandle, pipe_readmode_message, IntPtr.Zero, IntPtr.Zero))
					throw new Exception($"SetNamedPipeHandleState Error: {pipeName} isn't accessible, check to ensure OpenVPN Interactive Service is running");
				var taskCompletionSource = new TaskCompletionSource<int>();
				var afterRead = GetAfterReadDelegate(pipeName, readbuffer, taskCompletionSource, cancellationToken);
				var afterWrite = GetAfterWriteDelegate(readBufferSize, readbuffer, pipeHandle, taskCompletionSource, afterRead, cancellationToken);
				var naForWrite = new NativeOverlapped();
				var writefileresult = Native.WriteFileEx(pipeHandle,
						writebuffer,
						(uint)writebufferlength,
						ref naForWrite,
						afterWrite);
				if (!writefileresult)
				{
					var ex = new Win32Exception(Marshal.GetLastWin32Error(),
						$"{nameof(Call)} failed to run {nameof(Native.WriteFileEx)}");
					taskCompletionSource.SetException(ex);
					throw ex;
				}
				return await taskCompletionSource.Task.ConfigureAwait(false);
			}
			finally
			{
				Native.CloseHandle(pipeHandle);
				Marshal.FreeHGlobal(pipe_readmode_message);
				Marshal.FreeHGlobal(readbuffer);
				Marshal.FreeHGlobal(writebuffer);
			}
		}

		private static Native.WriteFileCompletionDelegate GetAfterWriteDelegate(int readBufferSize, IntPtr readbuffer, IntPtr pipeHandle, TaskCompletionSource<int> taskCompletionSource, IOCompletionCallback afterRead, CancellationToken cancellationToken)
		{
			return new Native.WriteFileCompletionDelegate((uint dwErrorCode, uint _, ref NativeOverlapped __) =>
			{
				if (dwErrorCode != 0)
				{
					taskCompletionSource.SetException(new Win32Exception((int)dwErrorCode, $"Error while waiting on {nameof(GetAfterWriteDelegate)}"));
				}
				else if (cancellationToken.IsCancellationRequested)
				{
					taskCompletionSource.SetException(new TaskCanceledException());
				}
				else
				{
					var naForRead = new NativeOverlapped();
					bool readFileResult;
					unsafe
					{
						readFileResult = Native.ReadFileEx(pipeHandle, readbuffer, (uint)readBufferSize, ref naForRead, afterRead);
					}
					if (!readFileResult)
					{
						taskCompletionSource.SetException(new Win32Exception(Marshal.GetLastWin32Error(),
							$"{nameof(GetAfterWriteDelegate)} failed to run {nameof(Native.ReadFileEx)}"));
					}
				}
			});
		}

		private static unsafe IOCompletionCallback GetAfterReadDelegate(string pipeName, IntPtr readbuffer, TaskCompletionSource<int> taskCompletionSource, CancellationToken cancellationToken)
		{
			return new IOCompletionCallback((uint errorCode, uint numBytes, NativeOverlapped* _) =>
			{
				if (errorCode != 0)
				{
					taskCompletionSource.SetException(new Win32Exception((int)errorCode, $"Error while waiting on {nameof(GetAfterReadDelegate)}"));
				}
				else if (cancellationToken.IsCancellationRequested)
				{
					taskCompletionSource.SetException(new TaskCanceledException($"Task cancelled in {nameof(GetAfterReadDelegate)}"));
				}
				else
				{
					var numBytesInt = (int)numBytes;
					var response = Encoding.Unicode.GetString(ToByteBuffer(readbuffer, numBytesInt), 0, numBytesInt);
					if (numBytes > 0)
					{
						var split = response.Split('\n');
						if (split[0].Equals("0x00000000") && split[2].Equals("Process ID"))
							taskCompletionSource.SetResult(int.Parse(split[1].Replace("0x", ""), System.Globalization.NumberStyles.HexNumber));
						else
							taskCompletionSource.SetException(new InteractiveServiceException(split[0], split[1], split[2]));
					}
					else
					{
						taskCompletionSource.SetException(new Exception($"Empty response from {pipeName}"));
					}
				}
			});
		}

		private static byte[] ToByteBuffer(IntPtr ptr, int length)
		{
			var buffer = new byte[length];
			for (var i = 0; i < length; i++)
			{
				buffer[i] = Marshal.ReadByte(ptr, i);
			}
			return buffer;
		}

		private static void FromByteBuffer(byte[] buffer, ref IntPtr ptr, int length)
		{
			for (var i = 0; i < length; i++)
			{
				Marshal.WriteByte(ptr, i, buffer[i]);
			}
		}
	}
}
