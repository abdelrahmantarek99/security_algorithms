using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public Dictionary<char, char> char_to_char;
        public void assign_char_char_equivalent(string key, bool plainToCipher = true)
        {
            char_to_char = new Dictionary<char, char>();
            if (plainToCipher)
            {
                for (int i = 0; i < key.Length; i++)
                {
                    int currChar_i = 97 + i;
                    char currChar_c = (char)currChar_i;
                    char_to_char.Add(currChar_c, key[i]);
                }
            }
            else
            {
                for (int i = 0; i < key.Length; i++)
                {
                    int currChar_i = 97 + i;
                    char currChar_c = (char)currChar_i;
                    char_to_char.Add(key[i], currChar_c);
                }
            }
        }
        public Dictionary<char, bool> createKeys()
        {
            Dictionary<char, bool> keys = new Dictionary<char, bool>();
            for (int i = 0; i < 26; i++)
            {
                int currChar_i = 97 + i;
                char currChar_c = (char)currChar_i;
                keys[currChar_c] = false;
            }
            return keys;
        }
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string key = "";
            char[] fakeArray = new char[26];
            Dictionary<char, bool> createKey = createKeys();
            List<char> key_list = fakeArray.ToList();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int charPlace = (int)plainText[i] - 97;
                key_list[charPlace] = cipherText[i];
                createKey[cipherText[i]] = true;
            }

            for (int i = 0; i < key_list.Count; i++)
            {
                if (!key_list[i].Equals('\0'))
                    key += key_list[i];
                else
                {
                    foreach (var key_val in createKey)
                    {
                        if (key_val.Value == false)
                        {
                            key += key_val.Key;
                            createKey[key_val.Key] = true;
                            break;
                        }

                    }
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            assign_char_char_equivalent(key, false);
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += char_to_char[cipherText[i]];
            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string encryptedStr = "";
            assign_char_char_equivalent(key);
            for (int i = 0; i < plainText.Length; i++)
            {
                encryptedStr += char_to_char[plainText[i]];
            }
            return encryptedStr;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51% 
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string key = "";
            cipher = cipher.ToLower();
            string priorityStr = "etaoinsrhldcumfpgwybvkxjqz";
            Dictionary<char, int> charFreq = new Dictionary<char, int>();
            Dictionary<char, char> char_to_char = new Dictionary<char, char>();
            foreach (char c in cipher)
            {
                if (charFreq.ContainsKey(c))
                    charFreq[c]++;
                else
                    charFreq.Add(c, 1);
            }
            var charFreqOrdered = charFreq.OrderByDescending(x => x.Value).ThenByDescending(x => x.Key).ToDictionary(x => x.Key, x => x.Value);
            int count = 0;
            foreach (var c in charFreqOrdered)
            {
                char_to_char.Add(c.Key, priorityStr[count++]);
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                key += char_to_char[cipher[i]];
            }

            return key;
        }
    }
}
