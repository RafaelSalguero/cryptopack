using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopack
{
    public class Hash
    {
        /// <summary>
        /// NOTE: SHA1 algorithm is broken by today standards and should not be used
        /// </summary>
        [Obsolete("SHA1 algorithm is broken by today standards and should not be used")]
        public static string SHA1(string Data)
        {
            return SHA1(Text.GetBytesFromString(Data));
        }

        /// <summary>
        /// NOTE: SHA1 algorithm is broken by today standards and should not be used
        /// </summary>
        [Obsolete("SHA1 algorithm is broken by today standards and should not be used")]
        public static string SHA1(byte[] data)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(data);
                return Text.ByteArrayToHexString(hash);
            }
        }

        /// <summary>
        /// Get the SHA256 of the given data.
        /// </summary>
        public static string SHA2(string Data)
        {
            return SHA2(Text.GetBytesFromString(Data));
        }

        /// <summary>
        /// Get the SHA256 of the given data.
        /// </summary>
        public static string SHA2(byte[] data)
        {
            using (SHA256Managed sha2 = new SHA256Managed())
            {
                var hash = sha2.ComputeHash(data);
                return Text.ByteArrayToHexString(hash);
            }
        }
    }
}
