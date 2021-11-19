using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    { 
        public string findKey(string fullkey) 
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
                for (int j = 0; j < fullkey.Length; j++)
                {
                    for (int y = 0; y < tmpKey.Length && j < fullkey.Length; y++)
                    {
                        if (fullkey[j] == tmpKey[y]) j++;
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

            ///computer
            ///hellohel
            ///jsxaiaic
            string fullkey = Decrypt(cipherText, plainText);

            
            return findKey(fullkey);
          
        }



        //**//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        static string calcDecrypt(string cipherText, string key, char[,] table)
        {
            string decreptedtext = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
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
            string keyStream = generateKeyStream(cipherText.Length, key);
            return calcDecrypt(cipherText,keyStream,table);
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
            string keyStream = generateKeyStream(plainText.Length, key);
            return calcEncrypt(plainText, keyStream , table);
        }


        //*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        static string generateKeyStream(int len, string key)
        {
            string keyStream = key;
            for (int i = 0; i < (len- key.Length); i++)
            {
                int a = i % key.Length;
                keyStream += key[a];
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