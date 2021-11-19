using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string findKey(string fullkey,string planetext)
        {
            for (int len = 1; len <= fullkey.Length; len++)
            {
                int i = 0;
                string tmpKey = "";
                while (i < len)
                {
                    tmpKey += fullkey[i];
                    i++;
                }
                ///check
                bool ok = true;
                for (int j = i; j < fullkey.Length; j++)
                {
                    for (int y = 0; y < planetext.Length && j < fullkey.Length; y++)
                    {
                        if (fullkey[j] == planetext[y]) j++;
                        else { ok = false; j = fullkey.Length + 5; break; }
                    }
                    j--;
                }
                ///
                if (ok) return tmpKey;
            }
            return "";
        }
        public string Analyse(string plainText, string cipherText)
        {
            string fullkey = Decrypt(cipherText, plainText);
            return findKey(fullkey,plainText);
        }

        //**//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        static string calcDecrypt(string cipherText,string key, char[,] table)
        {
            string decreptedtext = "";
            int idx = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {   if(i>=key.Length)
                {
                    key += decreptedtext[idx++];
                }
                int row = (int)(key[i] - 'a');
                for (int col = 0; col < 26; col++)
                {
                    if (cipherText[i] == table[row, col])
                        decreptedtext += (char)(col + 'a');
                }
            }
            return decreptedtext;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] table = new char[26, 26];
            table = generarteTable();
            return calcDecrypt(cipherText,key, table);
        }




        ///*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        static string calcEncrypt(string planeText, string key, char[,] table)
        {
            string encreptedtext = "";
            for (int i = 0; i < planeText.Length; i++)
            {
                int l = (int)(planeText[i] - 'a');
                int r = (int)(key[i] - 'a');
                encreptedtext += table[l, r];
            }
            return encreptedtext;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] table = new char[26, 26];
            table = generarteTable();
            string keyStream = generateKeyStream(plainText, key);
            return calcEncrypt(plainText, keyStream, table);
        }


        //*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        static string generateKeyStream(string planetext, string key)
        {
            string keyStream = key;
            for (int i = 0; i < (planetext.Length - key.Length); i++)
            {
                int a = i % planetext.Length;
                keyStream += planetext[a];
            }
            return keyStream;
        }
        static char[,] generarteTable()
        {
            char[,] table = new char[26, 26];
            int cnt = 0;
            for (int i = 0; i < 26; i++)
            {
                for (int y = 0; y < 26; y++)
                {
                    table[i, y] = (char)(cnt + 'A');
                    cnt++;
                    cnt %= 26;
                }
                cnt++;
            }

            return table;
        }
    }
}
