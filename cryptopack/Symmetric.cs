using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopack
{
    /// <summary>
    /// Metodos para encriptar simétricamente cadenas
    /// </summary>
    public static class Symmetric
    {
        /// <summary>
        /// Obtiene una contraseña derivada a de una llave pública
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string PasswordFromPublicKey(string publicKey)
        {
            var Params =
              Newtonsoft.Json.JsonConvert.DeserializeObject<DigitalSignatures.RSAParametersSerializable>(publicKey);

            return Text.ByteArrayToHexString(Params.Modulus) + ";" + Text.ByteArrayToHexString(Params.Exponent);
        }

        /// <summary>
        /// Realiza una encripción simétrica usando el algoritmo AES
        /// </summary>
        /// <param name="text">Texto a encriptar</param>
        /// <param name="password">Contraseña de la cual se van a derivar los bytes de la llave</param>
        public static string SimpleSymmetricDecrypt(string text, string password)
        {
            int Rfc2898KeygenIterations = 100;
            int AesKeySizeInBits = 128;
            byte[] salt = new byte[] { 132, 199, 135, 54, 237, 124, 78, 10, 42, 169, 237, 35, 102, 186, 74, 230 };
            byte[] cipherText = null;
            byte[] plainText = null;
            using (Aes aes = new AesManaged())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = AesKeySizeInBits;
                int KeyStrengthInBytes = aes.KeySize / 8;
                System.Security.Cryptography.Rfc2898DeriveBytes rfc2898 =
                    new System.Security.Cryptography.Rfc2898DeriveBytes(password, salt, Rfc2898KeygenIterations);
                aes.Key = rfc2898.GetBytes(KeyStrengthInBytes);
                byte[] IV = Text.HexStringToByteArray(text.Split(';')[0]);
                cipherText = Text.HexStringToByteArray(text.Split(';')[1]);
                aes.IV = IV;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherText, 0, cipherText.Length);
                    }
                    plainText = ms.ToArray();
                }

                return System.Text.Encoding.UTF8.GetString(plainText);
            }
        }


        /// <summary>
        /// Realiza una encripción simétrica usando el algoritmo AES
        /// </summary>
        /// <param name="text">Texto a encriptar</param>
        /// <param name="password">Contraseña de la cual se van a derivar los bytes de la llave</param>
        public static string SimpleSymmetricEncrypt(string text, string password)
        {
            int Rfc2898KeygenIterations = 100;
            int AesKeySizeInBits = 128;
            byte[] salt = new byte[] { 132, 199, 135, 54, 237, 124, 78, 10, 42, 169, 237, 35, 102, 186, 74, 230 };
            byte[] rawPlaintext = System.Text.Encoding.UTF8.GetBytes(text);
            byte[] cipherText = null;
            byte[] plainText = null;
            using (Aes aes = new AesManaged())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = AesKeySizeInBits;
                int KeyStrengthInBytes = aes.KeySize / 8;
                System.Security.Cryptography.Rfc2898DeriveBytes rfc2898 =
                    new System.Security.Cryptography.Rfc2898DeriveBytes(password, salt, Rfc2898KeygenIterations);
                aes.Key = rfc2898.GetBytes(KeyStrengthInBytes);
                byte[] IV = new byte[KeyStrengthInBytes];

                using (var R = new RNGCryptoServiceProvider())
                {
                    R.GetBytes(IV);
                }

                aes.IV = IV;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(rawPlaintext, 0, rawPlaintext.Length);
                    }
                    cipherText = ms.ToArray();
                }

                return Text.ByteArrayToHexString(IV) + ";" + Text.ByteArrayToHexString(cipherText);
            }
        }
    }
}
