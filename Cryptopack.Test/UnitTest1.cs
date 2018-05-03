using System;
using Cryptopack.Passwords;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptopack.Test
{
    [TestClass]
    public class UnitTest1
    {

        [TestMethod]
        public void SymmetricTest()
        {
            var texto = "Hola a todos";
            var pass = "123456";

            var cipher1 = Symmetric.SimpleSymmetricEncrypt(texto, pass);
            var cipher2 = Symmetric.SimpleSymmetricEncrypt(texto, pass);

            //Encriptar el mismo texto 2 veces no da lo mismo
            Assert.AreNotEqual(cipher1, cipher2);

            var plain1 = Symmetric.SimpleSymmetricDecrypt(cipher1, pass);
            var plain2 = Symmetric.SimpleSymmetricDecrypt(cipher2, pass);

            Assert.AreEqual(plain1, plain2);
            Assert.AreEqual(plain1, texto);

            try
            {
                var plainError = Symmetric.SimpleSymmetricDecrypt(cipher1, "1122");
            }
            catch (Exception)
            {
                return;
            }
            throw new Exception("No hubo error al desencriptar con la llave incorrecta");
        }
        [TestMethod]
        public void StoredPasswordTest()
        {
            var Password = "123";

            var St1 = StoredPassword.FromPlainText(Password).ToString();
            var St2 = StoredPassword.FromPlainText(Password).ToString();

            //Two stored password are different for the same password
            Assert.AreNotEqual(St1, St2);

            Assert.IsTrue(StoredPassword.TryFromString(St1).Value.Check(Password));
            Assert.IsTrue(StoredPassword.TryFromString(St2).Value.Check(Password));

            Assert.IsFalse(StoredPassword.TryFromString(St2).Value.Check("Wrong password"));
        }

        [TestMethod]
        public void DigitalSignaturesTest()
        {
            var Message1 = "This message is authentic";
            var Message2 = "This is not";

            var PrivateKey = DigitalSignatures.GeneratePrivateKey();
            var PublicKey = DigitalSignatures.GetPublicKeyFromPrivateKey(PrivateKey);

            var Signature = DigitalSignatures.SignData(Message1, PrivateKey);
            //Verify message:
            Assert.IsTrue(DigitalSignatures.VerifyData(Message1, Signature, PublicKey));
            Assert.IsFalse(DigitalSignatures.VerifyData(Message2, Signature, PublicKey));

        }

        public class DeclaracionDocumento
        {
            public DeclaracionDocumento(int cantidad, DateTime fecha, int otro)
            {
                Cantidad = cantidad;
                Fecha = fecha;
                Otro = otro;
            }

            public int Cantidad { get; set; }
            public DateTime Fecha { get; set; }
            public int Otro { get; set; }
        }

        public static string ObtenerCadenaOriginal(DeclaracionDocumento documento)
        {
            return $"{documento.Cantidad}|{documento.Fecha.ToString("yyyy-MMM-dd")}";
        }

        [TestMethod]
        public void Ejemplo()
        {
            var PrivateKey = DigitalSignatures.GeneratePrivateKey();
            var PublicKey = DigitalSignatures.GetPublicKeyFromPrivateKey(PrivateKey);

            //Esta en la partes secreta
            var informacion = new DeclaracionDocumento(1, new DateTime(2017, 3, 1), 39);
            var firma = DigitalSignatures.SignData(ObtenerCadenaOriginal(informacion), PrivateKey);

            //Cualquier otra persona
            var resultado = DigitalSignatures.VerifyData( ObtenerCadenaOriginal(informacion), firma, PublicKey);

            informacion = new DeclaracionDocumento(1, new DateTime(2017,7, 1), 39);

            var resultado2 = DigitalSignatures.VerifyData(ObtenerCadenaOriginal(informacion), firma, PublicKey);

        }
    }
}
