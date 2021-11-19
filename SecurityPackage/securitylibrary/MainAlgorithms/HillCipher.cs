using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {   public bool check_equality(List<int> newCipher, List<int> cipherText)
        {
            for (int i = 0; i < cipherText.Count; i++)
                if (cipherText[i] != newCipher[i]) return false;
            return true;
        }

        public List<int> bruteForce(List<int>plainText, List<int> cipherText)
        {
            List<int> tmp = new List<int>();
            for(int i=0;i<26;i++)
            {
                for(int j=0;j<26;j++)
                {
                    for(int k=0;k<26;k++)
                    {
                        for(int y=0;y<26;y++)
                        {
                           List<int>newCipher= Encrypt(plainText, new List<int>() { i, j, k, y });
                           bool wht=check_equality(newCipher,cipherText);
                           if(wht)
                            {
                                return new List<int>() { i, j, k, y };
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> Key= bruteForce(plainText,cipherText);
            int det = getDet2x2(Key);
            check1(det);
            return Key;
        }

        void check1(int det)
        {
            if(det !=1 && det!=-1) throw new NotImplementedException();

        }
        void check2(int det, int b, List<int> cipgher)
        {
            for (int i = 0; i < cipgher.Count; i++)
                if (cipgher[i] < 0 || cipgher[i] >= 26) throw new NotImplementedException();

            if (GCD(26, det) != 1 || det == 0 || b == -1) throw new NotImplementedException();

        }
        int GCD(int a, int b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }
            return a | b;
        }
        
        public int getDet2x2(List<int> l)
        {
            return ((l[0] * l[3]) - (l[1] * l[2]));
        }
        public List<int> getInv2x2(List<int> l)
        {
            l[1] *= -1;
            l[2] *= -1;
            int tmp = l[0];
            l[0] = l[3];
            l[3] = tmp;
            return l;
        }
        public List<int> detXmat(int Determent, List<int> inverseMAT)
        {
            int detInv = 1 / Determent;
            for (int i = 0; i < inverseMAT.Count; i++)
            {
                inverseMAT[i] = ((detInv * inverseMAT[i]) + 26) % 26;
            }
            return inverseMAT;
        }
        //*/////////
        public int fixMod(int num)
        {
            while (num < 0) num += 26;
            return num % 26;
        }
        public int getDet3x3(List<int> l)
        {
            int det = 0;
            List<int> mat1 = new List<int>() { l[4], l[5], l[7], l[8] };
            List<int> mat2 = new List<int>() { l[3], l[5], l[6], l[8] };
            List<int> mat3 = new List<int>() { l[3], l[4], l[6], l[7] };
            det = (l[0] * getDet2x2(mat1)) - (l[1] * getDet2x2(mat2)) + (l[2] * getDet2x2(mat3));
            return fixMod(det);
        }
        public int clacB(int det)
        {
            int b = 0;
            while ((b * det) % 26 != 1)
            {
                b++;
            }
            return b;
        }
        public List<int> getKeyInv(int B, List<int> key)
        {
            List<int> inv = new List<int>();
            inv.Add(fixMod((B * (int)Math.Pow(-1, 0) * getDet2x2(new List<int>() { key[4], key[5], key[7], key[8] })) % 26));
            inv.Add(fixMod((B * (int)Math.Pow(-1, 1) * getDet2x2(new List<int>() { key[3], key[5], key[6], key[8] })) % 26));
            inv.Add(fixMod((B * (int)Math.Pow(-1, 2) * getDet2x2(new List<int>() { key[3], key[4], key[6], key[7] })) % 26));
            inv.Add(fixMod((B * (int)Math.Pow(-1, 1) * getDet2x2(new List<int>() { key[1], key[2], key[7], key[8] })) % 26));
            inv.Add(fixMod((B * (int)Math.Pow(-1, 2) * getDet2x2(new List<int>() { key[0], key[2], key[6], key[8] })) % 26));
            inv.Add(fixMod((B * (int)Math.Pow(-1, 3) * getDet2x2(new List<int>() { key[0], key[1], key[6], key[7] })) % 26));
            inv.Add(fixMod((B * (int)Math.Pow(-1, 2) * getDet2x2(new List<int>() { key[1], key[2], key[4], key[5] })) % 26));
            inv.Add(fixMod((B * (int)Math.Pow(-1, 3) * getDet2x2(new List<int>() { key[0], key[2], key[3], key[5] })) % 26));
            inv.Add(fixMod((B * (int)Math.Pow(-1, 4) * getDet2x2(new List<int>() { key[0], key[1], key[3], key[4] })) % 26));

            return inv;
        }
        static List<int> getKeyTrans(List<int> keyInv)
        {
            List<int> trans = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0, y = i; j < 3; j++, y += 3)
                {
                    trans.Add(keyInv[y]);
                }
            }
            return trans;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            if (key.Count == 4)
            {
                int Determent = getDet2x2(key);
                List<int> inverseMAT = getInv2x2(key);
                Console.WriteLine(Determent);
                check1(Determent);
                inverseMAT = detXmat(Determent, inverseMAT);
                List<int> plain = Encrypt(cipherText, inverseMAT);
                return plain;
            }
            else if (key.Count == 9)
            {
                int det = getDet3x3(key);
                int B = -1;
                B=clacB(det);
                check2(det,B,key);
                List<int> keyInv = getKeyInv(B, key);
                List<int> keyTrans = getKeyTrans(keyInv);
                List<int> dec = Encrypt(cipherText, keyTrans);
                return dec;
            }

            return new List<int>();
        }
        //*//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        public int getM(List<int> Key)
        {
            for (int i = 1; i <= 100; i++)
            {
                if ((Key.Count / i) == i && (Key.Count % i) == 0) return i;
            }
            return -1;
        }
        public int colXcol(List<int> fi, List<int> se)
        {
            int sum = 0;
            for (int i = 0; i < fi.Count; i++)
            {
                sum += (fi[i] * se[i]);
            }
            return sum%26;
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int M = getM(key);
            double tmp = (double)(plainText.Count / M);
            int numOfColOfPlain = (int)Math.Ceiling(tmp);
            string Cipther = "";
            List<int> CList = new List<int>();
            ////
            List<int> PCol = new List<int>();
            List<int> KCol = new List<int>();
            for (int i = 1; i <= (M * numOfColOfPlain); i++)
            {
                if (i - 1 < plainText.Count)
                    PCol.Add(plainText[i - 1]);
                else
                    PCol.Add(0);
                ///
                if (i % M == 0)
                {   ///get col of key 
                    for (int j = 1; j <= key.Count; j++)
                    {
                        KCol.Add(key[j - 1]);
                        if (j % M == 0)
                        {
                            int num = colXcol(PCol, KCol);
                            CList.Add(num);

                            Cipther += (char) (num+'A');
                            KCol.Clear();
                        }
                    }
                    PCol.Clear();
                }
            }
            return CList;
        }
        //**///////////////////////////////////////////////////////////////////////////////////////////////
        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int det = getDet3x3(plainText);
            int B = -1;
            B = clacB(det);
            check2(det, B, plainText);
            List<int> keyInv = getKeyInv(B, plainText);
            List<int> keyTrans = getKeyTrans(keyInv);
            List<int> dec = Encrypt(getKeyTrans(cipherText), keyTrans);
            return dec;

        }

    }
}