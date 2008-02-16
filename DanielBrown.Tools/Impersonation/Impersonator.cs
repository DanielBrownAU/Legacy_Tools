using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Timers;

namespace DanielBrown.Tools.Impersonation
{
    public class Impersonator : IDisposable
    {
        #region Private Members
        private string m_Username = string.Empty;
        private string m_Password = string.Empty;
        private string m_Domain = string.Empty;
        
        private Timer m_ExpireTimer = new Timer();
        
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
            // revert back to original security context which was store in the WindowsImpersonationContext instance
            this.impersonationContext.Undo();
        }

        /// <summary>
        /// Diposes the Impersonator's resources and also calls Undo()
        /// </summary>
        public void Dispose()
        {
            this.Undo();
        }
    }
}