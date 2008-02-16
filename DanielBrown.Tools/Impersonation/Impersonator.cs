using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Timers;

namespace DanielBrown.Tools.Impersonation
{
    public class Impersonator : IDisposable
    {
        #region Private Members
        private string m_EventLogSource = "Impersonator";

        private string m_Username = string.Empty;
        private string m_Password = string.Empty;
        private string m_Domain = string.Empty;

        private Timer m_ExpireTimer = null;

        /// <summary>
        /// This will hold the security context for reverting back to the client after impersonation operations are complete
        /// </summary>
        private WindowsImpersonationContext impersonationContext = null;
        #endregion

        /// <summary>
        /// Disable instantiation via default constructor
        /// </summary>
        private Impersonator()
        {
            // Empty
        }

        private void m_ExpireTimer_Elapsed(object sender, ElapsedEventArgs e)
        {

            this.Undo();

            this.m_ExpireTimer.Stop();
            this.m_ExpireTimer.Close();
            this.m_ExpireTimer.Dispose();
        }

        /// <summary>
        /// Creates an im-memory instance of the Impersonator with the supplied values
        /// </summary>
        /// <param name="username">The Username of the User to impersonate</param>
        /// <param name="domain">The Domain ofthe User to impersonate</param>
        /// <param name="password">The Password of the User to imperonate</param>
        public Impersonator(string username, string domain, string password)
            : this()
        {

            // Sanity Checking!
            if (string.IsNullOrEmpty(username))
            {
                throw new LogonException("Invalid Username.");
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new LogonException("Invalid Password.");
            }

            // set the properties used for domain user account
            this.m_Username = username;

            if (domain == null) // need to figure out a way to set this to local machine
            {
                domain = string.Empty;
            }

            this.m_Domain = domain;
            this.m_Password = password;
        }

        /// <summary>
        /// Creates an im-memory instance of the Impersonator with the supplied values
        /// </summary>
        /// <param name="username">The Username of the User to impersonate</param>
        /// <param name="domain">The Domain ofthe User to impersonate</param>
        /// <param name="password">The Password of the User to imperonate</param>
        /// <param name="interval">Maximum amount of time before the timer fires and reverts to the previus context</param>
        public Impersonator(string username, string domain, string password, double interval)
            : this(username, domain, password)
        {
            this.m_ExpireTimer = new Timer(); // only create an instance of the timer, if they want to use it by using this constructor
            this.m_ExpireTimer.Interval = interval;
            this.m_ExpireTimer.Elapsed += new ElapsedEventHandler(m_ExpireTimer_Elapsed);
            this.m_ExpireTimer.Enabled = true;
            this.m_ExpireTimer.Start();
        }

        private WindowsIdentity Logon()
        {
            IntPtr handle = new IntPtr(0);

            try
            {
                handle = IntPtr.Zero;

                const int LOGON32_LOGON_NETWORK = 3;
                const int LOGON32_PROVIDER_DEFAULT = 0;

                // attempt to authenticate domain user account
                bool logonSucceeded = Shell32.LogonUser(this.m_Username, this.m_Domain, this.m_Password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, ref handle);

                if (!logonSucceeded)
                {
                    // if the logon failed, get the error code and throw an exception
                    throw new LogonException(string.Format(string.Format("User logon failed. Error Number: {0}", Marshal.GetLastWin32Error())));
                }

                // if logon succeeds, create a WindowsIdentity instance
                WindowsIdentity winIdentity = new WindowsIdentity(handle);

                return winIdentity;
            }
            finally
            {
                // close the open handle to the authenticated account
                Shell32.CloseHandle(handle);
            }
        }

        /// <summary>
        /// Attempts to authenticates the user account and begins impersonating it
        /// </summary>
        public void Impersonate()
        {
            this.impersonationContext = this.Logon().Impersonate();
        }

        /// <summary>
        /// Reverts to the previous user
        /// </summary>
        public void Undo()
        {
            try
            {
                this.Undo(); // Attempt 1: Undo()
            }
            catch (LogoffException le)
            {
                StringBuilder sbError = new StringBuilder();

                sbError.AppendLine("Unable to Undo Impersonation.");
                sbError.AppendLine(Environment.NewLine);
                sbError.AppendLine("Reason:");
                sbError.AppendLine(le.ToString());
                EventLog.WriteEntry(this.m_EventLogSource, sbError.ToString(), EventLogEntryType.Error);


                EventLog.WriteEntry(this.m_EventLogSource, "Attempting ExitWindowsEx", EventLogEntryType.Error);

                try
                {
                    // OK, DoUndo() has failed, try this, its hrash, but may be able to log off
                    this.TrySessionLogOff(); // Atemp 2: ExitWindowsEx
                }
                catch (LogoffException le2)
                {
                    EventLog.WriteEntry(this.m_EventLogSource, "FATAL ! WARNING ! ERROR ! Unable to revert back to previus user context! Code is still running under a different account!", EventLogEntryType.Error);
                    throw new ApplicationException("FATAL: Unable to logoff the impersonated user!", le2);
                }
            }
        }

        private void DoUndo()
        {
            // revert back to original security context which was store in the WindowsImpersonationContext instance
            try
            {
                this.impersonationContext.Undo();
            }
            catch (Exception e)
            {
                throw new LogoffException("Unable to Undo()", e);
            }
        }

        /// <summary>
        /// Diposes the Impersonator's resources and also calls Undo()
        /// </summary>
        public void Dispose()
        {
            // Revert back to the previous user context
            this.Undo();

            if (this.m_ExpireTimer != null) // check for null
            {
                // Dipose of the Timer
                this.m_ExpireTimer.Dispose();
            }
        }

        private void TrySessionLogOff()
        {
            int rval = Shell32.ExitWindowsEx(Shell32.EWX_LOGOFF | Shell32.EWX_FORCE | Shell32.EWX_FORCEIFHUNG, 0);

            if (rval == 0) // starting the shutdown failed
            {
                throw new LogoffException("FATAL: ExitWindowsEx Failed");
            }
        }
    }
}