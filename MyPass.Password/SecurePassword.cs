using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security;

namespace MyPass.SecurePassword
{

    public static class SecurePasswordHandler
    {
        public static unsafe T Use<T>(SecureString password, Func<byte[], T> f)
        {
            var maxLength = Encoding.UTF8.GetMaxByteCount(password.Length);
            var bytes = IntPtr.Zero;
            var passwordString = IntPtr.Zero;

            try
            {
                bytes = Marshal.AllocHGlobal(maxLength);
                passwordString = Marshal.SecureStringToBSTR(password);

                char* chars = (char*)passwordString.ToPointer();
                byte* bytePointer = (byte*)bytes.ToPointer();
                var length = Encoding.UTF8.GetBytes(chars, password.Length, bytePointer, maxLength);

                var passwordBytes = new byte[length];
                for (var i = 0; i < length; ++i)
                {
                    passwordBytes[i] = *bytePointer;
                    bytePointer++;
                }

                var result = f(passwordBytes);
                for (var i = 0; i < passwordBytes.Length; ++i) passwordBytes[i] = 0;
                return result;
            }
            finally
            {
                if (bytes != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(bytes);
                }
                if (passwordString != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(passwordString);
                }
            }
        }
    }
}