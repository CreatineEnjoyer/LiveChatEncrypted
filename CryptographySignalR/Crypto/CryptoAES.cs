using System.Security.Cryptography;

namespace CryptographySignalR.Crypto
{
    public class CryptoAES
    {
        /// <summary>
        /// Method to encrypt message using AES
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="key">Secret keyey used for algorithm</param>
        /// <param name="iv">Initialization vector for algorithm, created inside method</param>
        /// <returns>Encrypted message</returns>
        /// <exception cref="ArgumentNullException">In case, if one of params is null</exception>
        public static byte[] EncryptMessage(string message, byte[] key, out byte[] iv)
        {
            if (message == null || message.Length <= 0)
                throw new ArgumentNullException(nameof(message));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            //if (IV == null || IV.Length <= 0)
            //    throw new ArgumentNullException(nameof(IV));

            byte[] encrypted;

            // Create an Aes object with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                iv = aesAlg.IV;
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new())
                {
                    using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(message);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }


        /// <summary>
        /// Method to decrypt message using AES
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <param name="key">Secret keyey used for algorithm</param>
        /// <param name="iv">Initialization vector for algorithm</param>
        /// <returns>Decrypted message</returns>
        /// <exception cref="ArgumentNullException">In case, if one of params is null</exception>
        public static string DecryptMessage(byte[] encryptedMessage, byte[] key, byte[] iv)
        {
            if (encryptedMessage == null || encryptedMessage.Length <= 0)
                throw new ArgumentNullException(nameof(encryptedMessage));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException(nameof(iv));

            // Declare the string used to hold the decrypted text.
            string? decryptedMessage = null;

            // Create an Aes object with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new(encryptedMessage))
                {
                    using (CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream and place them in a string.
                            decryptedMessage = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return decryptedMessage;
        }
    }
}
