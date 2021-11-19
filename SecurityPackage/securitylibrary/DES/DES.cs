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
    public class DES : CryptographicTechnique
    {

        /// <summary>
        /// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /// </summary>

        int[] permutationTable = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
        int[] permutationTable2 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32, };
        int[] permutationTable3 = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
        int[] permutationTable4 = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
        int[] permutationTable5 = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

        int[,] sbx1 =
                      {{14, 4, 13, 1, 2, 15, 11, 8 ,3, 10, 6, 12, 5, 9, 0, 7 },
                        { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                        { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                        { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
                       };
        int[,] sbx2 = {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
            {3 ,13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9 ,11 ,5 },
            {0 ,14 ,7 ,11 ,10 ,4 ,13 ,1 ,5 ,8 ,12 ,6 ,9 ,3 ,2 ,15 },
            {13 ,8 ,10 ,1 ,3 ,15 ,4 ,2 ,11 ,6 ,7 ,12 ,0 ,5,14 ,9 }
        };
        int[,] sbx3 = {
            {10 ,0 ,9 ,14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
            {13 ,7 ,0 ,9 ,3 ,4, 6 ,10 ,2 ,8 ,5 ,14 ,12 ,11 ,15 ,1 },
            {13, 6 ,4 ,9 ,8 ,15, 3, 0 ,11, 1, 2, 12, 5, 10, 14, 7 },
            {1 ,10, 13 ,0 ,6 ,9 ,8 ,7 ,4 ,15 ,14 ,3 ,11 ,5 ,2, 12 }
        };
        int[,] sbx4 = {
            {7 ,13, 14, 3, 0 ,6 ,9 ,10, 1, 2, 8, 5, 11, 12, 4, 15 },
            {13 ,8, 11, 5, 6 ,15, 0, 3 ,4 ,7 ,2 ,12 ,1 ,10 ,14 ,9 },
            {10 ,6 ,9 ,0, 12, 11, 7 ,13 ,15 ,1 ,3, 14, 5, 2 ,8, 4 },
            {3 ,15, 0 ,6 ,10 ,1 ,13 ,8 ,9 ,4 ,5 ,11 ,12 ,7, 2 ,14 }
        };
        int[,] sbx5 = {
            {2, 12, 4 ,1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
            {14 ,11 ,2 ,12 ,4 ,7 ,13 ,1 ,5 ,0 ,15 ,10 ,3 ,9 ,8 ,6 },
            {4 ,2 ,1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
            {11 ,8 ,12 ,7 ,1 ,14 ,2 ,13 ,6 ,15 ,0 ,9 ,10 ,4 ,5 ,3 }
        };
        int[,] sbx6 = {
            {12 ,1 ,10 ,15 ,9 ,2 ,6 ,8, 0 ,13, 3, 4, 14, 7, 5 ,11 },
            {10 ,15 ,4 ,2 ,7 ,12, 9 ,5 ,6 ,1 ,13 ,14 ,0 ,11 ,3 ,8 },
            {9 ,14 ,15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
            {4 ,3 ,2, 12 ,9 ,5 ,15 ,10 ,11 ,14 ,1 ,7 ,6 ,0 ,8 ,13 }
        };
        int[,] sbx7 = {
            {4 ,11 ,2 ,14, 15, 0 ,8 ,13, 3 ,12, 9, 7, 5, 10, 6 ,1},
            {13 ,0, 11 ,7 ,4 ,9 ,1 ,10 ,14 ,3 ,5 ,12 ,2, 15 ,8 ,6},
            {1 ,4 ,11 ,13 ,12 ,3 ,7 ,14 ,10 ,15 ,6 ,8, 0 ,5, 9, 2},
            {6 ,11 ,13 ,8 ,1, 4, 10, 7, 9, 5, 0 ,15, 14 ,2, 3, 12}
        };
        int[,] sbx8 = {
            {13 ,2 ,8 ,4, 6, 15 ,11, 1 ,10, 9 ,3 ,14 ,5 ,0 ,12 ,7 },
            {1 ,15 ,13, 8, 10 ,3, 7 ,4, 12, 5 ,6 ,11 ,0 ,14, 9 ,2 },
            {7 ,11, 4 ,1 ,9 ,12, 14, 2, 0, 6, 10 ,13, 15 ,3 ,5, 8 },
            {2 ,1 ,14 ,7 ,4, 10, 8 ,13 ,15 ,12, 9 ,0 ,3, 5, 6, 11 }
        };

        string calcKFromPerTble(string combine, int[] permutationTable)
        {
            string s = "";
            for (int i = 0; i < permutationTable.Length; i++)
            {
                s += combine[permutationTable[i] - 1];
            }
            return s;
        }
        string conver2BinaryFromHex(string hex)
        {
            string bin = "";

            for (int i = 2; i < hex.Length; i++)
            {
                if (hex[i] == '0')
                    bin += "0000";
                else if (hex[i] == '1')
                    bin += "0001";
                else if (hex[i] == '2')
                    bin += "0010";
                else if (hex[i] == '3')
                    bin += "0011";
                else if (hex[i] == '4')
                    bin += "0100";
                else if (hex[i] == '5')
                    bin += "0101";
                else if (hex[i] == '6')
                    bin += "0110";
                else if (hex[i] == '7')
                    bin += "0111";
                else if (hex[i] == '8')
                    bin += "1000";
                else if (hex[i] == '9')
                    bin += "1001";
                else if (hex[i] == 'A')
                    bin += "1010";
                else if (hex[i] == 'B')
                    bin += "1011";
                else if (hex[i] == 'C')
                    bin += "1100";
                else if (hex[i] == 'D')
                    bin += "1101";
                else if (hex[i] == 'E')
                    bin += "1110";
                else if (hex[i] == 'F')
                    bin += "1111";

            }
            return bin;

        }

        List<string> calcKeys(string bin2)
        {
            string c0 = bin2.Substring(0, 28);
            string d0 = bin2.Substring(28, 28);

            bool[] vis = new bool[68];
            vis[0] = true;
            vis[1] = true;
            vis[8] = true;
            vis[15] = true;

            List<string> CList = new List<string>();
            List<string> DList = new List<string>();
            List<string> keys = new List<string>();
            CList.Add(c0);
            DList.Add(d0);
            ///
            for (int i = 0; i < 16; i++)
            {
                string tmpC = CList.Last(), tmpD = DList.Last();
                if (vis[i])
                {///shift 1 digit 
                    string c_alph = tmpC[0].ToString();
                    string d_alph = tmpD[0].ToString();
                    tmpC = tmpC.Remove(0, 1);
                    tmpC = tmpC.Insert(tmpC.Length, c_alph);
                    tmpD = tmpD.Remove(0, 1);
                    tmpD = tmpD.Insert(tmpD.Length, d_alph);
                }
                else
                {///shift 2 digits
                    string c_string = "";
                    c_string += tmpC[0];
                    c_string += tmpC[1];

                    string d_string = "";
                    d_string += tmpD[0];
                    d_string += tmpD[1];
                    tmpC = tmpC.Remove(0, 2);
                    tmpC = tmpC.Insert(tmpC.Length, c_string);
                    tmpD = tmpD.Remove(0, 2);
                    tmpD = tmpD.Insert(tmpD.Length, d_string);
                }
                CList.Add(tmpC);
                DList.Add(tmpD);
                string combine = tmpC + tmpD;

                string k = calcKFromPerTble(combine, permutationTable2);
                keys.Add(k);

            }
            return keys;
        }
        string expandR(string r)
        {
            string ExpandedR = "";
            ExpandedR += r[r.Length - 1];
            int i = 0;
            while (i < r.Length)
            {
                if (i - 1 >= 0)
                    ExpandedR += r[i - 1];
                for (int j = 0; j < 4; j++)
                    ExpandedR += r[i + j];

                i += 4;
                if (i < r.Length)
                    ExpandedR += r[i];
            }
            ExpandedR += r[0];
            return ExpandedR;
        }
        int convertFromBin2Dec(string n)
        {
            int ans = 0, tw = 1;
            int temp = int.Parse(n);
            while (temp > 0)
            {
                int last = temp % 10;
                temp = temp / 10;
                ans += last * tw;
                tw *= 2;
            }

            return ans;
        }
        string convertFromDec2Bin(int n)
        {
            string res = "";
            while (n > 0)
            {
                res = res.Insert(0, (n % 2).ToString());
                n = n / 2;
            }
            Console.WriteLine(res);
            int lim = (int)Math.Abs(4 - res.Length);
            for (int i = 0; i < lim; i++)
            {
                res = res.Insert(0, "0");
            }
            Console.WriteLine(res);
            Console.WriteLine(res.Length);
            return res;

        }
        string useSbox(string S_xor)
        {
            string res = "", tmp = "";
            int r, col;
            string a = S_xor.Substring(0, 6);
            tmp = "";
            tmp += a[0];
            tmp += a[5];
            r = convertFromBin2Dec(tmp);
            col = convertFromBin2Dec(a.Substring(1, 4));

            res += convertFromDec2Bin(sbx1[r, col]);
            Console.WriteLine(r + " " + col + " " + sbx1[r, col] + " " + convertFromDec2Bin(sbx1[r, col]));
            string b = S_xor.Substring(6, 6);
            tmp = "";
            tmp += b[0];
            tmp += b[5];
            r = convertFromBin2Dec(tmp);
            col = convertFromBin2Dec(b.Substring(1, 4));
            res += convertFromDec2Bin(sbx2[r, col]);

            string c = S_xor.Substring(12, 6);
            tmp = "";
            tmp += c[0];
            tmp += c[5];
            r = convertFromBin2Dec(tmp);
            col = convertFromBin2Dec(c.Substring(1, 4));
            res += convertFromDec2Bin(sbx3[r, col]);

            string d = S_xor.Substring(18, 6);
            tmp = "";
            tmp += d[0];
            tmp += d[5];
            r = convertFromBin2Dec(tmp);
            col = convertFromBin2Dec(d.Substring(1, 4));
            res += convertFromDec2Bin(sbx4[r, col]);

            string e = S_xor.Substring(24, 6);
            tmp = "";
            tmp += e[0];
            tmp += e[5];
            r = convertFromBin2Dec(tmp);
            col = convertFromBin2Dec(e.Substring(1, 4));
            res += convertFromDec2Bin(sbx5[r, col]);

            string f = S_xor.Substring(30, 6);
            tmp = "";
            tmp += f[0];
            tmp += f[5];
            r = convertFromBin2Dec(tmp);
            col = convertFromBin2Dec(f.Substring(1, 4));
            res += convertFromDec2Bin(sbx6[r, col]);

            string g = S_xor.Substring(36, 6);
            tmp = "";
            tmp += g[0];
            tmp += g[5];
            r = convertFromBin2Dec(tmp);
            col = convertFromBin2Dec(g.Substring(1, 4));
            res += convertFromDec2Bin(sbx7[r, col]);

            string h = S_xor.Substring(42, 6);
            tmp = "";
            tmp += h[0];
            tmp += h[5];
            r = convertFromBin2Dec(tmp);
            col = convertFromBin2Dec(h.Substring(1, 4));
            res += convertFromDec2Bin(sbx8[r, col]);


            return res;
        }
        string xoring(string a, string b)
        {
            string ans = "";
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == b[i])
                    ans += "0";
                else
                    ans += "1";
            }
            return ans;
        }
        string fn(string r, string l, string k)
        {
            string r_expanded = expandR(r);
            string S_xor = xoring(r_expanded, k);
            string r_xbox = useSbox(S_xor);
            string r_per = calcKFromPerTble(r_xbox, permutationTable4);
            string last = xoring(r_per, l);
            ///
            return last;
        }
        string convertFromBinToHex(string bin)
        {
            string hex = "";
            for (int i = 0; i < bin.Length; i += 4)
            {
                int j = 0;
                string tmp = "";
                while (j < 4)
                {
                    tmp += bin[i + j];
                    j++;
                }


                if ("0000" == tmp) hex += "0";
                else if ("0001" == tmp) hex += "1";
                else if ("0010" == tmp) hex += "2";
                else if ("0011" == tmp) hex += "3";
                else if ("0100" == tmp) hex += "4";
                else if ("0101" == tmp) hex += "5";
                else if ("0110" == tmp) hex += "6";
                else if ("0111" == tmp) hex += "7";
                else if ("1000" == tmp) hex += "8";
                else if ("1001" == tmp) hex += "9";
                else if ("1010" == tmp) hex += "A";
                else if ("1011" == tmp) hex += "B";
                else if ("1100" == tmp) hex += "C";
                else if ("1101" == tmp) hex += "D";
                else if ("1110" == tmp) hex += "E";
                else if ("1111" == tmp) hex += "F";
            }
            return hex;
        }



        ///*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ///Encryption and Decryption
        //*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        public override string Decrypt(string cipherText, string key)
        {
            string bin = conver2BinaryFromHex(key);
            string pertxt = calcKFromPerTble(bin, permutationTable);
            List<string> keys = calcKeys(pertxt);
            string txtBin = conver2BinaryFromHex(cipherText);
            string pertxt2 = calcKFromPerTble(txtBin, permutationTable3);
            string l0 = pertxt2.Substring(0, 32);
            string r0 = pertxt2.Substring(32, 32);
            List<string> L = new List<string>();
            List<string> R = new List<string>();
            L.Add(l0);
            R.Add(r0);
            for (int i = 0; i < 16; i++)
            {
                string tmp = fn(R.Last(), L.Last(), keys[16 - i - 1]);
                L.Add(R.Last());
                R.Add(tmp);
            }
            string swaping = "";
            swaping += R.Last();
            swaping += L.Last();
            string final = calcKFromPerTble(swaping, permutationTable5);
            ///
            return "0x" + convertFromBinToHex(final);
        }
        
        public override string Encrypt(string plainText, string key)
        {
            string bin = conver2BinaryFromHex(key);
            string pertxt = calcKFromPerTble(bin, permutationTable);
            List<string> keys = calcKeys(pertxt);
            string txtBin = conver2BinaryFromHex(plainText);
            string pertxt2 = calcKFromPerTble(txtBin, permutationTable3);
            string l0 = pertxt2.Substring(0, 32);
            string r0 = pertxt2.Substring(32, 32);
            List<string> L = new List<string>();
            List<string> R = new List<string>();
            L.Add(l0);
            R.Add(r0);
            for (int i = 0; i < 16; i++)
            {
                string tmp = fn(R.Last(), L.Last(), keys[i]);
                L.Add(R.Last());
                R.Add(tmp);
            }
            string swaping = "";
            swaping += R.Last();
            swaping += L.Last();
            string final = calcKFromPerTble(swaping, permutationTable5);
            ///
            return "0x"+convertFromBinToHex(final);
        }
    }
}
