using System;
using System.Security.Cryptography;
using System.Text;

namespace LANCHAT2
{
    public class EncryptionHelper
    {
        private static readonly string Key = "KluczSzyfrowania123"; // Klucz szyfrowania

        private static byte[] GetAesKey()
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(Key);
                byte[] hashedBytes = sha256.ComputeHash(keyBytes);
                byte[] aesKey = new byte[32];
                Array.Copy(hashedBytes, aesKey, 32);
                return aesKey;
            }
        }

        public static string Encrypt(string input)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            using (Aes aes = Aes.Create())
            {
                aes.Key = GetAesKey();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);

                encryptor.Dispose();

                byte[] combinedBytes = new byte[aes.IV.Length + encryptedBytes.Length];
                Array.Copy(aes.IV, combinedBytes, aes.IV.Length);
                Array.Copy(encryptedBytes, 0, combinedBytes, aes.IV.Length, encryptedBytes.Length);

                string encryptedString = Convert.ToBase64String(combinedBytes);
                return encryptedString;
            }
        }

        public static string Decrypt(string encryptedInput)
        {
            byte[] combinedBytes = Convert.FromBase64String(encryptedInput);

            using (Aes aes = Aes.Create())
            {
                aes.Key = GetAesKey();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[aes.IV.Length];
                byte[] cipherText = new byte[combinedBytes.Length - iv.Length];
                Array.Copy(combinedBytes, iv, iv.Length);
                Array.Copy(combinedBytes, iv.Length, cipherText, 0, cipherText.Length);

                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);

                decryptor.Dispose();

                string decryptedString = Encoding.UTF8.GetString(decryptedBytes);
                return decryptedString;
            }
        }
    }
}

