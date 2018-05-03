using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrivateKeyGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            var pk = Cryptopack.DigitalSignatures.GeneratePrivateKey();


            Console.WriteLine(pk);
            System.IO.File.WriteAllText("./pk.json", pk);
            Console.ReadKey();
        }
    }
}
