using System;

namespace DanielBrown.Tools.Impersonation
{
    public class LogonException : Exception
    {
        public LogonException(string Message)
            : base(Message)
        {
        }

        public LogonException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
