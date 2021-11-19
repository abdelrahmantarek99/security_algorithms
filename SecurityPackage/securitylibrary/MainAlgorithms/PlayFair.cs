using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string original = "";
            key = GetUniqueChars(key.ToLower());
            char[,] arr = new char[5, 5];
            arr = fillMatrix(key);
            Dictionary<char, KeyValuePair<int, int>> indxs = new Dictionary<char, KeyValuePair<int, int>>();
            for (int i = 0; i < 5; ++i)
            {
                for (int j = 0; j < 5; ++j)
                {
                    indxs[arr[i, j]] = new KeyValuePair<int, int>(i, j);
                }
            }
            indxs['j'] = new KeyValuePair<int, int>(5, 5);
            string tmp;
            List<string> lst = new List<string>();
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                tmp = "";
                tmp += cipherText[i];
                tmp += cipherText[i + 1];
                lst.Add(convert(tmp, arr, indxs, false));
            }

            for (int i = 0; i < lst.Count; i++)
            {
                if (i == lst.Count - 1)
                {
                    if (lst[i][1] == 'x') original += lst[i][0];
                    else original += lst[i];
                }
                else
                {
                    if (lst[i][1] == 'x' && lst[i][0] == lst[i + 1][0])
                    {
                        original += lst[i][0];
                        original += lst[i + 1];
                        ++i;
                    }
                    else original += lst[i];
                }
            }
            return original;
        }

        public string Encrypt(string plainText, string key)
        {
            string encrypted = "";
            key = GetUniqueChars(key.ToLower());
            plainText = plainText.ToLower();
            char[,] arr = new char[5, 5];
            arr = fillMatrix(key);
            Dictionary<char, KeyValuePair<int, int>> indxs = new Dictionary<char, KeyValuePair<int, int>>();
            for (int i = 0; i < 5; ++i)
            {
                for (int j = 0; j < 5; ++j)
                {
                    indxs[arr[i, j]] = new KeyValuePair<int, int>(i, j);
                }
            }
            indxs['j'] = new KeyValuePair<int, int>(5, 5);
            string tmp;
            for (int i = 0; i < plainText.Length; i += 2)
            {
                tmp = "";
                if (i == plainText.Length - 1)
                {
                    tmp += plainText[i];
                    tmp += 'x';
                    encrypted += convert(tmp, arr, indxs, true);
                }
                else
                {
                    if (plainText[i] == plainText[i + 1])
                    {
                        tmp += plainText[i];
                        tmp += 'x';
                        encrypted += convert(tmp, arr, indxs, true);
                        --i;
                    }
                    else
                    {
                        tmp += plainText[i];
                        tmp += plainText[i + 1];
                        encrypted += convert(tmp, arr, indxs, true);
                    }
                }
            }
            return encrypted;
        }
        static string convert(string plainText, char[,] arr, Dictionary<char, KeyValuePair<int, int>> indxs, bool encrpt)
        {
            string ans = "";
            int i = 0;
            int val;
            if (encrpt == true) val = 1;
            else val = 4;
            if (indxs[plainText[i]].Key == indxs[plainText[i + 1]].Key)
            {
                int row = indxs[plainText[i]].Key;
                int nxtCol1 = (indxs[plainText[i]].Value + val) % 5;
                int nxtCol2 = (indxs[plainText[i + 1]].Value + val) % 5;
                ans += arr[row, nxtCol1];
                ans += arr[row, nxtCol2];
            }
            else if (indxs[plainText[i]].Value == indxs[plainText[i + 1]].Value)
            {
                int col = indxs[plainText[i]].Value;
                int nxtRow1 = (indxs[plainText[i]].Key + val) % 5;
                int nxtRow2 = (indxs[plainText[i + 1]].Key + val) % 5;
                ans += arr[nxtRow1, col];
                ans += arr[nxtRow2, col];
            }
            else
            {
                int frstRow, frstCol, scndRow, scndCol;
                frstRow = indxs[plainText[i]].Key; frstCol = indxs[plainText[i]].Value;
                scndRow = indxs[plainText[i + 1]].Key; scndCol = indxs[plainText[i + 1]].Value;
                ans += arr[frstRow, scndCol];
                ans += arr[scndRow, frstCol];
            }
            return ans;

        }

        static string GetUniqueChars(string plainText)
        {
            HashSet<char> charSet = new HashSet<char>();
            string unique = "";
            for (int i = 0; i < plainText.Length; ++i)
            {
                if (charSet.Contains(plainText[i]) == false)
                {
                    unique += plainText[i];
                    charSet.Add(plainText[i]);
                }
            }
            return unique;
        }
        static char[,] fillMatrix(string key)
        {
            char[,] arr = new char[5, 5];
            int pntrArr = 0, pntrList = 0;
            List<char> alphaBet = new List<char>();
            for (int i = 0; i < 26; ++i)
            {
                if (97 + i == 106) continue;// don't add letter j
                alphaBet.Add((char)(97 + i));// add abcdefgh........
            }
            for (int i = 0; i < 5; ++i)
            {
                for (int j = 0; j < 5; ++j)
                {
                    if (pntrArr < key.Length)
                    {
                        if (key[pntrArr] == 'j')
                        {
                            alphaBet.Remove('i');
                            arr[i, j] = 'i';
                        }
                        else
                        {
                            alphaBet.Remove(key[pntrArr]);
                            arr[i, j] = key[pntrArr];
                        }
                        pntrArr++;
                    }
                    else
                    {
                        arr[i, j] = alphaBet[pntrList++];
                    }
                }
            }
            return arr;
        }
    }
}
