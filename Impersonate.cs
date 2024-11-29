using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Impersonate
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Write("CurrentUser:");
                PrintWindowsIdentity(WindowsIdentity.GetCurrent());
                Console.Write("AnonymousUser:");
                PrintWindowsIdentity(WindowsIdentity.GetAnonymous());
            }
            else if (args.Length == 1)
            {
                if (args[0] == "?")
                {
                    Usage();
                }
                else
                {
                    string username = args[0];
                    WindowsIdentity identity = new WindowsIdentity(username);
                    PrintWindowsIdentity(identity);
                }
            }
            else
            {
                string username = args[0];
                string password = args[1];
                string domain = ".";

                if (args.Length > 2)
                {
                    domain = args[2];
                }

                // Console.WriteLine("==== Before logon user ====");
                // PrintWindowsIdentity(WindowsIdentity.GetCurrent());
                // PrintCurrentThread();

                Console.WriteLine("==== Logon user ====");

                IntPtr tokenHandle = IntPtr.Zero;

                // Attempt to log the user on
                bool success = LogonUser(
                    username,
                    domain,
                    password,
                    (int)LogonType.LOGON32_LOGON_INTERACTIVE,
                    (int)LogonProvider.LOGON32_PROVIDER_DEFAULT,
                    out tokenHandle);

                if (success)
                {
                    try
                    {
                        Console.WriteLine("==== Before impersonate the logon user ====");
                        PrintWindowsIdentity(WindowsIdentity.GetCurrent());
                        PrintCurrentThread();

                        using (WindowsImpersonationContext context = WindowsIdentity.Impersonate(tokenHandle))
                        {
                            Console.WriteLine("==== Impersonating the logon user ====");
                            PrintWindowsIdentity(WindowsIdentity.GetCurrent());
                            PrintCurrentThread();
                        }
                    }
                    finally
                    {
                        // Close the token handle
                        CloseHandle(tokenHandle);
                    }
                }
                else
                {
                    Console.WriteLine("Logon failed with error code: " + Marshal.GetLastWin32Error());
                }
            }
        }

        public enum LogonType : int
        {
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS = 9
        }

        public enum LogonProvider : int
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr hObject);

        // Import the GetCurrentThreadId function from kernel32.dll
        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        // Import the GetCurrentThread function from kernel32.dll
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        // Import the necessary functions from advapi32.dll
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalAlloc(uint uFlags, uint uBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        private const uint LMEM_FIXED = 0x0000;
        private const uint LMEM_ZEROINIT = 0x0040;

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenPrivileges = 3
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        static void Usage()
        {
            Console.WriteLine($"{Environment.CommandLine.Split(' ').First().Trim('"')} <user name> <password> <domain>");
        }

        static void PrintWindowsIdentity(WindowsIdentity identity)
        {
            int i;
            Console.WriteLine("Name: " + identity.Name);
            Console.WriteLine("Authentication Type: " + identity.AuthenticationType);
            Console.WriteLine($"Is [Anonymous|Authenticated|Guest|System]: [{identity.IsAnonymous}|{identity.IsAuthenticated}|{identity.IsGuest}|{identity.IsSystem}]");
            Console.WriteLine("ImpersonationLevel: " + identity.ImpersonationLevel);
            Console.Write("Owner:");
            PrintSecurityIdentifier(identity.Owner);
            Console.WriteLine("Token: " + identity.Token);
            PrintTokenPrivileges(identity.Token);
            Console.WriteLine($"ClaimsCount:{identity.Claims.Count()}");
            i = 0;
            /*
            foreach (Claim claim in identity.Claims)
            {
                Console.Write($"Claim {i++}:");
                PrintClaim(claim);
            }
            Console.WriteLine($"DeviceClaimsCount: {identity.DeviceClaims.Count()}");
            i = 0;
            foreach(Claim claim in identity.DeviceClaims)
            {
                Console.WriteLine($"DeviceClaim {i++}:");
                PrintClaim(claim);
            }
            Console.WriteLine($"UserClaimsCount: {identity.UserClaims.Count()}");
            i = 0;
            foreach (Claim claim in identity.UserClaims)
            {
                Console.WriteLine($"UserClaim {i++}:");
                PrintClaim(claim);
            }
            Console.WriteLine($"GroupsCount: {identity.Groups.Count}");
            i = 0;
            foreach(IdentityReference ir in identity.Groups)
            {
                Console.WriteLine($"Group {i++}:");
                PrintIdentityReference(ir);
            }
            */
        }

        static void PrintClaim(Claim claim)
        {
            Console.WriteLine(claim.ToString());
            /*
            Console.WriteLine("Claim Type: " + claim.Type);
            Console.WriteLine("Claim Value: " + claim.Value);
            Console.WriteLine("Value Type: " + claim.ValueType);
            Console.WriteLine("Issuer: " + claim.Issuer);
            Console.WriteLine("Original Issuer: " + claim.OriginalIssuer);
            */
        }

        static void PrintIdentityReference(IdentityReference identityReference)
        {
            Console.WriteLine(identityReference.Value);

            if (identityReference.IsValidTargetType(typeof(NTAccount)))
            {
                PrintNTAccount(identityReference as NTAccount);
            }

            if (identityReference.IsValidTargetType(typeof(SecurityIdentifier)))
            {
                PrintSecurityIdentifier(identityReference as SecurityIdentifier);
            }
        }

        static void PrintNTAccount(NTAccount account)
        {
            if (account == null)
            {
                Console.WriteLine("NTAccount is null");
            }
            else
            {
                Console.WriteLine("NTAccount: " + account.ToString());
            }
        }

        static void PrintSecurityIdentifier(SecurityIdentifier identifier)
        {
            if (identifier == null)
            {
                Console.WriteLine("SecurityIdentifier is null");
            }
            else
            {
                Console.WriteLine("SecurityIdentifier: " + identifier.ToString());
            }
        }

        static void PrintCurrentThread()
        {
            Thread thread = Thread.CurrentThread;

            Console.WriteLine("Thread ID: " + thread.ManagedThreadId);
            Console.WriteLine("Thread Name: " + thread.Name);
            Console.WriteLine("Thread State: " + thread.ThreadState);
            Console.WriteLine($"Is [Background|ThreadPool]: [{thread.IsBackground}|{thread.IsThreadPoolThread}]");

            IPrincipal principal = Thread.CurrentPrincipal;
            Console.WriteLine($"Thread Principal: {principal.Identity.Name}");
            Console.WriteLine($"Is Authenticated: {principal.Identity.IsAuthenticated}");
            Console.WriteLine($"AuthenticationType: {principal.Identity.AuthenticationType}");

            Console.WriteLine($"Current native thread id: {GetCurrentThreadId()}");
        }

        static void PrintTokenPrivileges(IntPtr tokenHandle)
        {
            // Get the size of the TOKEN_PRIVILEGES structure
            uint tokenInfoLength = 0;
            GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out tokenInfoLength);

            // Allocate memory for the TOKEN_PRIVILEGES structure
            IntPtr tokenInfo = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, tokenInfoLength);

            try
            {
                // Get the token privileges
                if (GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, tokenInfo, tokenInfoLength, out tokenInfoLength))
                {
                    TOKEN_PRIVILEGES privileges;

                    // Read the PrivilegeCount
                    privileges.PrivilegeCount = (uint)Marshal.ReadInt32(tokenInfo);
                    privileges.Privileges = new LUID_AND_ATTRIBUTES[privileges.PrivilegeCount];

                    // Calculate the starting point of the privileges array in the buffer
                    IntPtr privilegesPtr = IntPtr.Add(tokenInfo, sizeof(uint));

                    // Marshal each LUID_AND_ATTRIBUTES structure from the buffer
                    for (int i = 0; i < privileges.PrivilegeCount; i++)
                    {
                        privileges.Privileges[i] = Marshal.PtrToStructure<LUID_AND_ATTRIBUTES>(IntPtr.Add(privilegesPtr, i * Marshal.SizeOf<LUID_AND_ATTRIBUTES>()));
                    }

                    // Print the privileges
                    Console.WriteLine("Privileges:");
                    for (int i = 0; i < privileges.PrivilegeCount; i++)
                    {
                        LUID_AND_ATTRIBUTES luidAndAttributes = privileges.Privileges[i];
                        Console.WriteLine($"  LUID: {luidAndAttributes.Luid.LowPart}-{luidAndAttributes.Luid.HighPart}, Attributes: {luidAndAttributes.Attributes}");
                    }
                }
                else
                {
                    Console.WriteLine("Failed to get token privileges. Error code: " + Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                // Free the allocated memory
                LocalFree(tokenInfo);
            }
        }
    }
}
