using System;
using System.Runtime.InteropServices;

namespace DanielBrown.Tools
{
    internal class Shell32
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("user32")]
        internal extern static int ExitWindowsEx(int uFlags, int dwReason);
        internal static readonly int EWX_LOGOFF = 0;
        internal static readonly int EWX_FORCE = 4;
        internal static readonly int EWX_FORCEIFHUNG = 10;

    }
}
