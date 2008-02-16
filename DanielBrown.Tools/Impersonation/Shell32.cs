using System;
using System.Runtime.InteropServices;

namespace DanielBrown.Tools
{
    public class Shell32
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("user32")]
        public extern static int ExitWindowsEx(int uFlags, int dwReason);
        public static readonly int EWX_LOGOFF = 0;
        public static readonly int EWX_FORCE = 4;
        public static readonly int EWX_FORCEIFHUNG = 10;

    }
}
