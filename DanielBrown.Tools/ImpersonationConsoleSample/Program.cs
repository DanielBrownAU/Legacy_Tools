using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using DanielBrown.Tools.Impersonation;

namespace ImpersonationConsoleSample
{
    class Program
    {
        static void Main(string[] args)
        {
            Impersonator i = null;
            try
            {
                // Change theses to a user on your domain
                string SampleUsername = "testuser";
                string SamplePassword = "password";
                string SampleDomain = "";

                // Say Current User
                Console.WriteLine(System.Security.Principal.WindowsIdentity.GetCurrent().Name);

                #region Impersonating a User
                i = new Impersonator(SampleUsername, SampleDomain, SamplePassword);

                i.Impersonate();

                // ... Run Code
                // ...

                // Say Current User
                Console.WriteLine(System.Security.Principal.WindowsIdentity.GetCurrent().Name);

                i.Undo();
                #endregion

                // Say Current User
                Console.WriteLine(System.Security.Principal.WindowsIdentity.GetCurrent().Name);

                #region Impersonating a User with the using cluase
                using (Impersonator im = new Impersonator(SampleUsername, SampleDomain, SamplePassword))
                {
                    im.Impersonate();
                    // ... Run Code
                    // ...

                    // Say Current User
                    Console.WriteLine(System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                }
                #endregion

                Console.WriteLine(System.Security.Principal.WindowsIdentity.GetCurrent().Name);

                #region Impersonating a User with a Timer
                i = new Impersonator(SampleUsername, SampleDomain, SamplePassword, 100);

                i.Impersonate();

                // ... Run Code
                System.Threading.Thread.Sleep(1000);

                // Say Current User
                Console.WriteLine(System.Security.Principal.WindowsIdentity.GetCurrent().Name);

                //TODO: Fix duplicat emessage in event log
                // i.Undo(); // NOTE: Note needed with a timer! but can be called.
                
                #endregion
            }
            catch (LogonException le)
            {
                Console.WriteLine(le.ToString());
            }
            finally
            {
                // Say Current User
                Console.WriteLine(System.Security.Principal.WindowsIdentity.GetCurrent().Name);

                Console.ReadLine();
            }
        }
    }
}



