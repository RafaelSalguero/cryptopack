using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopack.Passwords
{
    /// <summary>
    /// Implementation of the PBKDF2 algorithm that can be used to validate a password that can be safely stored, since it's imposible to get the original password back from this information. It is secure to serialize and store this structure without further encryption
    /// </summary>
    public struct StoredPassword
    {
        /// <summary>
        /// Default number of iterations of the PBKDF2 algorithm
        /// </summary>
        public const int DefaultIterations = 10000;

        /// <summary>
        /// Create a new store password from a plain text password
        /// </summary>
        private StoredPassword(string PlainText, int Iterations = DefaultIterations)
        {
            byte[] passSalt = new byte[32];
            using (var R = new RNGCryptoServiceProvider())
            {
                R.GetBytes(passSalt);
            }

            this.Iterations = Iterations;
            Salt = passSalt;
            Hash = HashPassword(Text.GetBytesFromString(PlainText), passSalt, Iterations);
        }

        /// <summary>
        /// Create a new store password from a plain text with a given salt and iteration count
        /// </summary>
        private StoredPassword(string PlainText, int Iterations, byte[] Salt)
        {
            this.Iterations = Iterations;
            this.Salt = Salt;
            Hash = HashPassword(Text.GetBytesFromString(PlainText), this.Salt, Iterations);
        }


        /// <summary>
        /// Create an stored password from parameters
        /// </summary>
        /// <param name="Iterations">Number of iterations of the stored password</param>
        /// <param name="Salt">Salt of the store password</param>
        /// <param name="Hash">Result of the last hash iteration</param>
        public StoredPassword(int Iterations, byte[] Salt, byte[] Hash)
        {
            this.Iterations = Iterations;
            this.Salt = Salt;
            this.Hash = Hash;
        }

        /// <summary>
        /// Deserialize an string with Iterations;Hex(Salt);Hex(Hash) to an store password
        /// </summary>
        /// <param name="SemicolonSeparatedString">A string with iterations, hex(salt) and hex(hash) separated by semicolons</param>
        /// <returns></returns>
        public static StoredPassword FromString(string SemicolonSeparatedString)
        {
            var S = SemicolonSeparatedString.Split(';');
            var Ret = new StoredPassword(int.Parse(S[0]), Text.HexStringToByteArray(S[1]), Text.HexStringToByteArray(S[2]));
            return Ret;
        }

        /// <summary>
        /// Create an irreversible stored password from a Plain text password
        /// </summary>
        /// <param name="PlainText">Plain text to store securely</param>
        /// <returns></returns>
        public static StoredPassword FromPlainText(string PlainText)
        {
            return new StoredPassword(PlainText);
        }

        /// <summary>
        /// Hash iterations
        /// </summary>
        public readonly int Iterations;

        /// <summary>
        /// Password wide salt. This salt is a random number unique to this password
        /// </summary>
        public readonly byte[] Salt;


        /// <summary>
        /// The hash of the stored password
        /// </summary>
        public readonly byte[] Hash;

        /// <summary>
        /// Check if a given password is correct
        /// </summary>
        /// <param name="PlainText">The password to check</param>
        /// <returns></returns>
        public bool Check(string PlainText)
        {
            var St = new StoredPassword(PlainText, Iterations, Salt);
            return St.Hash.SequenceEqual(Hash);
        }

        /// <summary>
        /// Return a string with Iterations;HexString(Salt);HexString(Hash)
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"{Iterations};{Text.ByteArrayToHexString(Salt)};{Text.ByteArrayToHexString(Hash)}";
        }

        /// <summary>
        /// Gets a password hash using a system wide salt and the PBKDF2 algorithm
        /// </summary>
        /// <param name="Password">The password to hash</param>
        /// <param name="PasswordWideSalt">A random number</param>
        /// <param name="Iterations">The number of iterations</param>
        /// <returns></returns>
        private static byte[] HashPassword(byte[] Password, byte[] PasswordWideSalt, int Iterations = DefaultIterations)
        {
            byte[] fullSalt = new byte[PasswordWideSalt.Length];
            Array.Copy(PasswordWideSalt, 0, fullSalt, 0, PasswordWideSalt.Length);
            byte[] hashed;
            using (Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(Password, fullSalt, Iterations))
            {
                hashed = k1.GetBytes(32);
            }

            return hashed;
        }
    }
}
