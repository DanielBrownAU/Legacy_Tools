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

        private IntPtr tokenHandle = new IntPtr(0);
        

        private string m_EventLogSource = "Impersonator";

        private string m_Username = string.Empty;
        private string m_Password = string.Empty;
        private string m_Domain = string.Empty;

        private Timer m_ExpireTimer = null;

        private WindowsIdentity m_impersonationIdentity = null;
        /// <summary>
        /// This will hold the security context for reverting back to the client after impersonation operations are complete
        /// </summary>
        private WindowsImpersonationContext m_impersonationContext = null;

        private WindowsIdentity m_OriginalIdentity = null;
        private WindowsImpersonationContext m_OrginalConext = null;
        #endregion

        /// <summary>
        /// Disable instantiation via default constructor
        /// </summary>
        private Impersonator()
        {
            this.m_OriginalIdentity = System.Security.Principal.WindowsIdentity.GetCurrent(); // Orginal Identify

            if (!EventLog.SourceExists(this.m_EventLogSource)) // Check to see if the Event Source is created
            {
                EventLog.CreateEventSource(this.m_EventLogSource, this.m_EventLogSource); // Create the Event Source
            }
        }

        private void m_ExpireTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            this.WriteToEventLog("Timer has Expired! Reverting Code!", EventLogEntryType.Information);
            this.m_ExpireTimer.Stop();
            this.m_ExpireTimer.Close();
            this.m_ExpireTimer.Dispose();

            this.Undo();

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
        }

        private WindowsIdentity Logon()
        {
            try
            {
                const int LOGON32_LOGON_NETWORK = 3;
                const int LOGON32_PROVIDER_DEFAULT = 0;

                // attempt to authenticate domain user account
                bool logonSucceeded = Shell32.LogonUser(this.m_Username, this.m_Domain, this.m_Password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, ref tokenHandle);

                if (!logonSucceeded)
                {
                    this.WriteToEventLog(string.Format("Impersonation failed for user: {0}", this.m_Username), EventLogEntryType.Error);
                    // if the logon failed, get the error code and throw an exception
                    throw new LogonException(string.Format(string.Format("User logon failed. Error Number: {0}", Marshal.GetLastWin32Error())));
                }

                // if logon succeeds, create a WindowsIdentity instance
                m_impersonationIdentity = new WindowsIdentity(tokenHandle);

                this.m_ExpireTimer.Start();

                this.WriteToEventLog(string.Format("Success! Impersonate user: {0}", this.m_Username), EventLogEntryType.Information);

                return m_impersonationIdentity;
            }
            finally
            {

            }
        }

        /// <summary>
        /// Attempts to authenticates the user account and begins impersonating it
        /// </summary>
        public void Impersonate()
        {
            this.WriteToEventLog(string.Format("Attempting to Impersonate user: {0}", this.m_Username), EventLogEntryType.Information);
            this.m_impersonationContext = this.Logon().Impersonate();
        }

        /// <summary>
        /// Reverts to the previous user
        /// </summary>
        public void Undo()
        {
            try
            {
                this.WriteToEventLog(string.Format("Attempting to Undo impersonation of user: {0}", this.m_Username), EventLogEntryType.Information);
                this.DoUndo(); // Attempt 1: DoUndo()
            }
            catch (LogoffException le)
            {

                StringBuilder sbError = new StringBuilder();

                sbError.AppendLine("Unable to Undo Impersonation.");
                sbError.AppendLine(Environment.NewLine);
                sbError.AppendLine("Reason:");
                sbError.AppendLine(le.ToString());

                this.WriteToEventLog(sbError.ToString(), EventLogEntryType.Error);


                this.WriteToEventLog("Attempting ExitWindowsEx", EventLogEntryType.Warning);
                m_OrginalConext.Undo();
                try
                {
                    // OK, DoUndo() has failed, try this, its hrash, but may be able to log off
                    this.TrySessionLogOff(); // Atemp 2: ExitWindowsEx
                }
                catch (LogoffException le2)
                {
                    this.WriteToEventLog("FATAL ! WARNING ! ERROR ! Unable to revert back to previus user context! Code is still running under a different account!", EventLogEntryType.Error);
                    StringBuilder sbError1 = new StringBuilder();
                    sbError1.AppendLine("Unable to Undo Impersonation.");
                    sbError1.AppendLine(Environment.NewLine);
                    sbError1.AppendLine("Reason:");
                    sbError1.AppendLine(le2.ToString());
                    this.WriteToEventLog(sbError1.ToString(), EventLogEntryType.Error);

                    throw new ApplicationException("FATAL: Unable to logoff the impersonated user!", le2);
                }
            }
        }

        private void WriteToEventLog(string Message, EventLogEntryType Type)
        {
            m_OrginalConext = m_OriginalIdentity.Impersonate();
            EventLog.WriteEntry(this.m_EventLogSource, Message, Type);
            m_OrginalConext.Undo();
        }

        private void DoUndo()
        {
            // revert back to original security context which was store in the WindowsImpersonationContext instance
            try
            {
                this.m_impersonationContext.Undo();
            }
            catch (Exception e)
            {
                this.WriteToEventLog("Unable to Undo()", EventLogEntryType.Error);
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

            // close the open handle to the authenticated account
            Shell32.CloseHandle(tokenHandle);
        }

        private void TrySessionLogOff()
        {
            int rval = Shell32.ExitWindowsEx(Shell32.EWX_LOGOFF | Shell32.EWX_FORCE | Shell32.EWX_FORCEIFHUNG, 0);

            if (rval == 0) // starting the shutdown failed
            {
                this.WriteToEventLog("FATAL: ExitWindowsEx Failed", EventLogEntryType.Error);
                throw new LogoffException("FATAL: ExitWindowsEx Failed");
            }
        }

        public WindowsImpersonationContext ImpersonationContext
        {
            get
            {
                return this.m_impersonationContext;
            }
        }
    }
}