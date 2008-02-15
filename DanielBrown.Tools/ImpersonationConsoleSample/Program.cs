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
            // Change theses to a user on your domain
            string SampleUsername = "Username";
            string SamplePassword = "password1";
            string SampleDomain = "domain";

            // Impersonating a User
            Impersonator i = new Impersonator(SampleUsername, SampleDomain, SamplePassword);
            i.Impersonate();
            // .. Run Code
            i.Undo();

            // Impersonating a User with the using cluase
            using (Impersonator im = new Impersonator(SampleUsername, SampleDomain, SamplePassword))
            {
                // ... Run Code
            }            
        }
    }
}
