using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace MiniDump
{
    class Program
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFile(string filename, Int32 access, Int32 share, IntPtr securityAttributes, Int32 creationDisposition, Int32 flagsAndAttributes, IntPtr templateFile);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(Int32 processAccess, bool bInheritHandle, Int32 processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string dll);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string name);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool MiniDumpWriteDump(IntPtr hProcess, Int32 ProcessId, IntPtr hFile, Int32 DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        static void Main(string[] args)
        {
            Int32 PID = Convert.ToInt32(args[0]);
            IntPtr hFile = IntPtr.Zero;
            IntPtr hProc = IntPtr.Zero;
            bool bSuccess = false;


            IntPtr createPtr = GetProcAddress(LoadLibrary("Dbghelp.dll"), "MiniDumpWriteDump");
            MiniDumpWriteDump miniDumpWriteDump = (MiniDumpWriteDump)Marshal.GetDelegateForFunctionPointer(createPtr, typeof(MiniDumpWriteDump));

            Console.WriteLine("MiniDumpWriteDump found at 0x{0}", createPtr.ToString("X"));
            // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ = 1040
            hProc = OpenProcess(1040, false, PID);
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
            Console.WriteLine("Process Completed ({0})(%ld)", bSuccess);
        }
    }
}
