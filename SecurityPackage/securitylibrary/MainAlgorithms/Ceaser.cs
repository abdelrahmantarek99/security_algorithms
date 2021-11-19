using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        Dictionary<char, int> char_to_numeric;
        public void assign_char_numeric_equivalent()
        {
            char_to_numeric = new Dictionary<char, int>();

            for (int i = 0; i < 26; i++)
            {
                int currChar_i = 97 + i;
                char currChar_c = (char)currChar_i;
                char_to_numeric.Add(currChar_c, i);
            }
        }
        public int calculate_CT_index(int key, int PT_index)
        {
            return (PT_index + key) % 26;
        }
        public string Encrypt(string plainText, int key)
        {
            assign_char_numeric_equivalent();
            plainText = plainText.ToLower();
            string encryptedStr = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int currChar = calculate_CT_index(key, char_to_numeric[plainText[i]]) + 97;
                encryptedStr += (char)currChar;
            }
            return encryptedStr.ToUpper();
        }
        public int PT_index(int key, int CT_index)
        {
            int calcIndex = CT_index - key;
            return (calcIndex < 0) ? 26 + calcIndex : (CT_index - key) % 26;
        }
        public string Decrypt(string cipherText, int key)
        {
            assign_char_numeric_equivalent();
            cipherText = cipherText.ToLower();
            string plainText = "";
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int currChar = PT_index(key, char_to_numeric[cipherText[i]]) + 97;
                plainText += (char)currChar;
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            assign_char_numeric_equivalent();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                int currKey = (int)cipherText[i] - (int)plainText[i];
                if (currKey < 0)
                    key = 26 - Math.Abs(currKey);
                else
                    key = currKey;
            }
            return key;
        }
    }
}
