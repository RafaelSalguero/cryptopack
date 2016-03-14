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

            var St1 = new StoredPassword(Password).ToString();
            var St2 = new StoredPassword(Password).ToString();

            //Two stored password are different for the same password
            Assert.AreNotEqual(St1, St2);

            Assert.IsTrue(StoredPassword.FromString(St1).Check(Password));
            Assert.IsTrue(StoredPassword.FromString(St2).Check(Password));

            Assert.IsFalse(StoredPassword.FromString(St2).Check("Wrong password"));
        }
    }
}
