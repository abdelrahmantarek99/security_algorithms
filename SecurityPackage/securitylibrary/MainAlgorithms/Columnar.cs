using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int> >
    {
        public  char[,] makePTable(string text, int numOfRows, int numCol2)
        {
            int idx = 0;
            char[,] table = new char[numOfRows, numCol2];

            for (int i = 0; i < numOfRows; i++)
            {
                for (int y = 0; y < numCol2; y++)
                {
                    if (idx < text.Length)
                    {
                        table[i, y] = text[idx++];
                        Console.Write(table[i, y] + " ");
                    }


                }
                Console.WriteLine();
            }
            return table;
        }
        public  char[,] makeCTable(string text, char[,] ptable, int numOfRows, int numCol2)
        {
            int idx = 0;
            char[,] table = new char[numOfRows, numCol2];

            for (int i = 0; i < numCol2; i++)
            {
                for (int y = 0; y < numOfRows; y++)
                {
                    if (idx < text.Length)
                    {
                        table[y, i] = text[idx++];
                    }


                }
            }
            return table;
        }
        public  List<int> search(string plainText2, string cipherText, int numOfRows, int numCol2)
        {
            List<int> l = new List<int>();
            bool[] visC = new bool[cipherText.Length];
            bool[] visP = new bool[plainText2.Length];
            int ans = 0;
            for (int occ = 0; occ < plainText2.Length; occ++)
            {
                for (int i = 0; i < plainText2.Length; i++)
                {
                    string fi = ""; int a = 0;
                    while (i + a < plainText2.Length && a < numOfRows && !visP[i + a])
                    {
                        fi += plainText2[i + a];
                        a++;
                    }
                    ////////////////////////////////////////////
                    for (int y = 0; y < cipherText.Length; y++)
                    {
                        string se = "";
                        for (int j = y; j < cipherText.Length && j < y + numOfRows && !visC[j]; j++)
                        {
                            se += cipherText[j];
                            if (fi == se && (fi.Length != 0))
                            {
                                Console.WriteLine(fi);

                                ////make vis 
                                for (int w = y; w < cipherText.Length && w < y + numOfRows && !visC[w]; w++)
                                {
                                    visC[w] = true;
                                }
                                a = 0;
                                while (i + a < plainText2.Length && a < numOfRows && !visP[i + a])
                                {
                                    visP[i + a] = true;
                                    a++;
                                }

                                /*for (int g = 0; g < cipherText.Length; g++)
                                    Console.Write(visP[g] + " *");

                                Console.WriteLine();

                                for (int g = 0; g < cipherText.Length; g++)
                                    Console.Write(visC[g] + "- ");
                                
                                Console.WriteLine();*/
                                ///////end vis
                                i += (fi.Length - 1);
                                Console.WriteLine(i);
                                ans++;
                                int save = 0;
                                for (int z = 0; z < cipherText.Length; z += numOfRows)
                                {
                                    if (j >= z) save++;
                                }
                                l.Add(save);

                                y = cipherText.Length + 5;
                                break;
                            }
                        }
                        ///////////check 

                    }
                }
            }
            Console.WriteLine("ans =" + ans);
            return l;

        }
        public  string makePText(char[,] plainTable, int numOfRows, int numCol2)
        {
            string s = "";
            for (int i = 0; i < numCol2; i++)
            {
                for (int y = 0; y < numOfRows; y++)
                {
                    if (plainTable[y, i] >= 'a' && plainTable[y, i] <= 'z')
                        s += plainTable[y, i];
                }
            }
            return s;
        }
        public  List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            Console.WriteLine(plainText.Length);
            for (int numOfRows = 2; numOfRows <= cipherText.Length; numOfRows++)
            {
                double numCol1 = (double)cipherText.Length / numOfRows;
                int numCol2 = (int)Math.Ceiling(numCol1);
                char[,] plainTable = new char[numOfRows, numCol2];
                char[,] cipherTable = new char[numOfRows, numCol2];

                ///make plain table
                plainTable = makePTable(plainText, numOfRows, numCol2);
                string plainText2 = makePText(plainTable, numOfRows, numCol2);
                Console.WriteLine(plainText2);
                Console.WriteLine(cipherText);
                ///make cipher table
                //cipherTable = makeCTable(cipherText, plainTable, numOfRows, numCol2);


                List<int> l = search(plainText2, cipherText, numOfRows, numCol2);
                Console.WriteLine(numOfRows + " " + l.Count);
                if (l.Count == numCol2) return l;
            }
            ///
            return new List<int>();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText= cipherText.ToLower(); 
            int mxCol2 = key.Count;
            double mxrows1 = (double)cipherText.Length / mxCol2;
            int mxrows2 = (int)Math.Ceiling(mxrows1);
            int idx = 0;
            char[,] table = new char[mxrows2, mxCol2];
            string decryptedText = "";
            ///making table 
            for (int i = 0; i < mxCol2; i++)
            {
                for (int y = 0; y <mxrows2; y++)
                {
                    if (idx < cipherText.Length)
                    {
                        table[ y, i ] = cipherText [idx++];
                    }
                }
            }
            ////iterate on table
            for (int i = 0; i < mxrows2; i++)
            {
                for (int y = 0; y < mxCol2; y++)
                {  
                    decryptedText += table[i, key[y]-1];
                }
            }
            return decryptedText.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int mxCol2 = key.Count;

            double mxrows1 = (double)plainText.Length / mxCol2;
            int mxrows2 = (int)Math.Ceiling(mxrows1);
            int idx = 0;
            char[,] table = new char[mxrows2, mxCol2];
            string encryptedText = "";
            ///making table 
            for (int i = 0; i < mxrows2; i++)
            {
                for (int y = 0; y < mxCol2; y++)
                {
                    if (idx < plainText.Length)
                    {
                        table[i, key[y] - 1] = plainText[idx++];
                    }
                }
            }
            ////iterate on table
            for (int i = 0; i < mxCol2; i++)
            {
                for (int y = 0; y < mxrows2; y++)
                {
                    encryptedText += table[y, i ];
                }
            }
           return encryptedText.ToUpper();

        }
    }
}

 
 