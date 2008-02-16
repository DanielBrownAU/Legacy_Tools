using System;

namespace DanielBrown.Tools.Impersonation
{
    public class LogoffException : Exception
    {
        public LogoffException(string Message)
            : base(Message)
        {
        }

        public LogoffException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
