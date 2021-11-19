using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            for (int key_siz = 1; key_siz <= plainText.Length; key_siz++)
            {
                bool ok = true;
                int idx = 0;

                for (int r = 0; r < key_siz; r++)
                {
                    for (int i = r; i < plainText.Length; i += key_siz)
                    {
                        if (plainText[i] != cipherText[idx++])
                            ok = false;

                    }
                }

                if (ok == true) { return key_siz; }

            }
            return -1;

        }

        public string Decrypt(string cipherText, int key)
        {
            double mxCol = (double)cipherText.Length / key;
            int mxCol2 = (int)Math.Ceiling(mxCol);
            int idx = 0;
            char[,] table = new char[key, mxCol2];
            string decryptedText = "";
            ///making table  but iterate on it directly
            for (int i = 0; i < key; i++)
            {
                for (int y = 0; y < mxCol2; y++)
                {
                    if (idx < cipherText.Length)
                        table[i,y] = cipherText[idx++];
                }
            }
            ////iterate on table by up and  down column
            for (int i = 0; i < mxCol2; i++)
            {
                for (int y = 0; y < key; y++)
                {
                    decryptedText += table[y, i];
                }
            }
            return decryptedText.ToLower();

        }

        public string Encrypt(string plainText, int key)
        {
            double mxCol = (double) plainText.Length / key;
            int mxCol2 = (int) Math.Ceiling(mxCol);
            int idx = 0;
            char[,] table = new char[key,mxCol2];
            string encryptedText = "";
            ///making table 
            for(int i=0;i<mxCol2;i++)
            {
             for(int y=0;y<key;y++)
                {   if(idx<plainText.Length)
                    table[y, i] = plainText[idx++];
                }
            }
            ////iterate on table
            for (int i = 0; i < key; i++)
            {
                for (int y = 0; y <mxCol2; y++)
                {
                       encryptedText+=table[i, y];
                }
            }
            return encryptedText.ToUpper();
        }
    }
}
