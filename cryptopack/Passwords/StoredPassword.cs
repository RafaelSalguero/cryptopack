using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopack.Passwords
{
    /// <summary>
    /// Implementation of the PBKDF2 algorithm that can be used to validate a password that can be safely stored, 
    /// since it's imposible to get the original password back from this information.
    /// It is secure to serialize and store this structure without further encryption.
    /// 
    /// To securely save a password use the FromPlainText method and then store the ToString result
    /// To check a password try to deserialize the stored password using the FromString method and then use the Check method
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
        private StoredPassword(string plainText, int iterations = DefaultIterations)
        {
            byte[] passSalt = new byte[32];
            using (var R = new RNGCryptoServiceProvider())
            {
                R.GetBytes(passSalt);
            }

            this.Iterations = iterations;
            Salt = passSalt;
            Key = DerivePassword(Text.GetBytesFromString(plainText), passSalt, iterations);
        }

        /// <summary>
        /// Create a new store password from a plain text with a given salt and iteration count
        /// </summary>
        private StoredPassword(string plainText, int iterations, byte[] salt)
        {
            this.Iterations = iterations;
            this.Salt = salt;
            Key = DerivePassword(Text.GetBytesFromString(plainText), this.Salt, iterations);
        }


        /// <summary>
        /// Create an stored password from parameters
        /// </summary>
        /// <param name="iterations">Number of iterations of the stored password</param>
        /// <param name="salt">Salt of the store password</param>
        /// <param name="hash">Result of the last hash iteration</param>
        public StoredPassword(int iterations, byte[] salt, byte[] hash)
        {
            this.Iterations = iterations;
            this.Salt = salt;
            this.Key = hash;
        }


        /// <summary>
        /// Deserialize an string with Iterations;Hex(Salt);Hex(Key) to an store password. If the string is malformed returns null
        /// </summary>
        /// <param name="semicolonSeparatedString">The serialized stored password.</param>
        /// <returns></returns>
        public static StoredPassword? TryFromString(string semicolonSeparatedString)
        {
            try
            {
                var S = semicolonSeparatedString.Split(';');
                var Ret = new StoredPassword(int.Parse(S[0]), Text.HexStringToByteArray(S[1]), Text.HexStringToByteArray(S[2]));
                return Ret;
            }
            catch (Exception)
            {
                return null;
            }
            
        }

        /// <summary>
        /// Create an irreversible stored password from a plain text password
        /// </summary>
        /// <param name="plainText">Plain text to store securely</param>
        /// <returns></returns>
        public static StoredPassword FromPlainText(string plainText)
        {
            return new StoredPassword(plainText);
        }

        /// <summary>
        /// Create an irreversible stored password from a plain text password.
        /// Use the Check method later to check for password correctness
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static string StorePlainText(string plainText)
        {
            return FromPlainText(plainText).ToString();
        }

        /// <summary>
        /// Check if the given plain text is equal to the one that originated the stored password
        /// </summary>
        /// <param name="storedPassword">The stored password</param>
        /// <param name="plainText">The plain text to check</param>
        /// <returns>Returns true if the plain text password is correct</returns>
        public static bool Check( string storedPassword, string plainText)
        {
            return TryFromString(storedPassword)?.Check(plainText) ?? false;
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
        /// A 256-bit key derived from the original password and the given salt
        /// </summary>
        public readonly byte[] Key;

        /// <summary>
        /// Check if a given password is correct
        /// </summary>
        /// <param name="plainText">The password to check</param>
        /// <returns></returns>
        public bool Check(string plainText)
        {
            var St = new StoredPassword(plainText, Iterations, Salt);
            return St.Key.SequenceEqual(Key);
        }

        /// <summary>
        /// Serialize the stored password into an string with the following format:
        /// Iterations;hex(salt);hex(Key)
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"{Iterations};{Text.ByteArrayToHexString(Salt)};{Text.ByteArrayToHexString(Key)}";
        }

        /// <summary>
        /// Derive a key from a password using the the PBKDF2 algorithm
        /// </summary>
        /// <param name="Password">The password to hash</param>
        /// <param name="PasswordWideSalt">A random number, unique per password</param>
        /// <param name="Iterations">The number of iterations</param>
        /// <returns>256 bit key derived from the password and the salt</returns>
        private static byte[] DerivePassword(byte[] Password, byte[] PasswordWideSalt, int Iterations = DefaultIterations)
        {
            byte[] key;
            using (Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(Password, PasswordWideSalt, Iterations))
            {
                key = k1.GetBytes(32);
            }
            return key;
        }
    }
}
