﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Cryptopack
{
    /// <summary>
    /// Contains methods for managing digital signatures
    /// </summary>
    public static class DigitalSignatures
    {
        public class RSAParametersSerializable 
        {
            private RSAParameters _rsaParameters;

            [JsonIgnore]
            public RSAParameters RSAParameters
            {
                get
                {
                    return _rsaParameters;
                }
            }

            public RSAParametersSerializable(RSAParameters rsaParameters)
            {
                _rsaParameters = rsaParameters;
            }

            private RSAParametersSerializable()
            {
            }

            public byte[] D { get { return _rsaParameters.D; } set { _rsaParameters.D = value; } }

            public byte[] DP { get { return _rsaParameters.DP; } set { _rsaParameters.DP = value; } }

            public byte[] DQ { get { return _rsaParameters.DQ; } set { _rsaParameters.DQ = value; } }

            public byte[] Exponent { get { return _rsaParameters.Exponent; } set { _rsaParameters.Exponent = value; } }

            public byte[] InverseQ { get { return _rsaParameters.InverseQ; } set { _rsaParameters.InverseQ = value; } }

            public byte[] Modulus { get { return _rsaParameters.Modulus; } set { _rsaParameters.Modulus = value; } }

            public byte[] P { get { return _rsaParameters.P; } set { _rsaParameters.P = value; } }

            public byte[] Q { get { return _rsaParameters.Q; } set { _rsaParameters.Q = value; } }
           
        }
        /// <summary>
        /// Gets a JSON serialized random RSA private key
        /// </summary>
        /// <returns></returns>
        public static string GeneratePrivateKey()
        {
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            var R = RSA.ExportParameters(true);

            var ret = Newtonsoft.Json.JsonConvert.SerializeObject(new RSAParametersSerializable(R), Newtonsoft.Json.Formatting.Indented);
            return ret;
        }

        /// <summary>
        /// Gets a JSON serialized public key from a full private key
        /// </summary>
        /// <returns></returns>
        public static string GetPublicKeyFromPrivateKey(string PrivateKey)
        {
            var Params =
                Newtonsoft.Json.JsonConvert.DeserializeObject<RSAParametersSerializable>(PrivateKey);

            RSAParameters DRet = new RSAParameters();
            DRet.Modulus = Params.Modulus;
            DRet.Exponent = Params.Exponent;

            var ret = Newtonsoft.Json.JsonConvert.SerializeObject(new RSAParametersSerializable(DRet), Newtonsoft.Json.Formatting.Indented);
            return ret;
        }

        /// <summary>
        /// Returns a signed hash of the given data which can be used to prove that the data was signed by the owner a given known public key
        /// </summary>
        /// <param name="Data">The data to sign</param>
        /// <param name="PrivateKey">The private key</param>
        public static string SignData(string Data, string PrivateKey)
        {
            return SignData(Text.GetBytesFromString(Data), PrivateKey);
        }

        /// <summary>
        /// Returns the base 64 encoded signed hash of the given data which can be used to prove that the data was signed by the owner of a known public key
        /// </summary>
        /// <param name="Data">The data to sign</param>
        /// <param name="PrivateKey">The private key</param>
        /// <returns></returns>
        public static string SignData(byte[] Data, string PrivateKey)
        {
            var HashValue = Text.HexStringToByteArray(Hash.SHA2(Data));

            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

            var Params =
                Newtonsoft.Json.JsonConvert.DeserializeObject<RSAParametersSerializable>(PrivateKey);
            RSA.ImportParameters(Params.RSAParameters);

            RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(RSA);

            RSAFormatter.SetHashAlgorithm("SHA256");

            //Create a signature for HashValue and assign it to 
            //SignedHashValue.
            var SignedHashValue = RSAFormatter.CreateSignature(HashValue);

            return Convert.ToBase64String(SignedHashValue);
        }

        /// <summary>
        /// Returns true if the data is correctly signed by the owner of the given public key
        /// </summary>
        /// <param name="Data">The data to verify</param>
        /// <param name="DigitalSignature">The signed hash of the given data</param>
        /// <param name="PublicKey">The public key of the owner of the private key used to signing the data</param>
        /// <returns></returns>
        public static bool VerifyData(string Data, string DigitalSignature, string PublicKey)
        {
            return VerifyData(Text.GetBytesFromString(Data), DigitalSignature, PublicKey);
        }

        /// <summary>
        /// Returns true if the data is correctly signed
        /// </summary>
        /// <param name="Data">The data to verify</param>
        /// <param name="PublicKey">The public key of the owner of the private key used to signing the data</param>
        /// <param name="DigitalSignature">The digital signature generated with the data and the private key</param>
        /// <returns></returns>
        public static bool VerifyData(byte[] Data, string DigitalSignature, string PublicKey)
        {
            var HashValue = Text.HexStringToByteArray(Hash.SHA2(Data));
            var SignedHashValue = Convert.FromBase64String(DigitalSignature);
            var Params =
                        Newtonsoft.Json.JsonConvert.DeserializeObject<RSAParametersSerializable>(PublicKey);

            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSA.ImportParameters(Params.RSAParameters);
            RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
            RSADeformatter.SetHashAlgorithm("SHA256");

            return RSADeformatter.VerifySignature(HashValue, SignedHashValue);
        }
    }
}
