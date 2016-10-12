using System;
using Cryptopack.Passwords;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cryptopack.Test
{
    [TestClass]
    public class UnitTest1
    {
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
    }
}
