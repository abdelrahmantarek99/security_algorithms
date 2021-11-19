using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES obj = new DES();
            string a = obj.Decrypt(cipherText, key[0]);
            string b = obj.Encrypt(a, key[1]);
            string c = obj.Decrypt(b, key[0]);
            return c;
        }

        public string Encrypt(string plainText, List<string> key)
        {   
            DES obj = new DES();
            string a = obj.Encrypt(plainText,key[0]);
            string b = obj.Decrypt(a, key[1]);
            string c = obj.Encrypt(b, key[0]);
            return c;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {   
            throw new NotSupportedException();
        }

    }
}
