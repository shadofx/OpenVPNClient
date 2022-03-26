using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Threading;

namespace OpenVPNClient
{
	[SupportedOSPlatform("windows")]
	internal static class Native
	{
		// Win32 constants for accessing files.
		internal const uint GENERIC_READ = 0x80000000;
		internal const uint GENERIC_WRITE = 0x40000000;
		internal const uint FILE_FLAG_OVERLAPPED = 0x40000000;
		internal const uint PIPE_READMODE_MESSAGE = 0x00000002;

		// Allocate a file object in the kernel, then return a handle to it.
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		internal extern static IntPtr CreateFile(string fileName,
			uint dwDesiredAccess, FileShare dwShareMode,
			IntPtr securityAttrs_MustBeZero, FileMode dwCreationDisposition,
			uint dwFlagsAndAttributes, IntPtr hTemplateFile_MustBeZero);

		[DllImport("kernel32.dll")]
		internal static extern bool SetNamedPipeHandleState(IntPtr hNamedPipe, IntPtr lpMode,
			IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout);

		//https://www.pinvoke.net/default.aspx/kernel32/WriteFileEx.html
		[DllImport("kernel32.dll")]
		internal static extern bool WriteFileEx(IntPtr hFile, IntPtr lpBuffer,
			uint nNumberOfBytesToWrite, [In] ref NativeOverlapped lpOverlapped,
			WriteFileCompletionDelegate lpCompletionRoutine);
		internal delegate void WriteFileCompletionDelegate(uint dwErrorCode,
		  uint dwNumberOfBytesTransfered, ref NativeOverlapped lpOverlapped);

		//https://www.pinvoke.net/default.aspx/kernel32/ReadFileEx.html
		[DllImport("kernel32.dll",SetLastError = true)]
		internal static extern bool ReadFileEx(IntPtr hFile, IntPtr lpBuffer,
			uint nNumberOfBytesToRead, [In] ref NativeOverlapped lpOverlapped,
			IOCompletionCallback lpCompletionRoutine);

		[DllImport("kernel32.dll", SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern bool GetOverlappedResult(IntPtr hFile, [In] ref NativeOverlapped lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait);
	}

}
