using System.Security.Cryptography;

namespace CryptographySignalR.Crypto
{
    public class CryptoRSA
    {
        /// <summary>
        /// Method used for encrypting data using RSA algorithm
        /// </summary>
        /// <param name="DataToEncrypt">Data to encrypt</param>
        /// <param name="RSAKeyInfo">Used as receiver's public key</param>
        /// <returns>Encrypted data</returns>
        public static byte[]? RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACng RSA = new())
                {
                    //Import the RSA Key information. This only needs to include the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding. OAEP padding is only available on Microsoft Windows XP or later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, RSAEncryptionPadding.OaepSHA256);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }


        /// <summary>
        /// Method used for decrypting data using RSA algorithm
        /// </summary>
        /// <param name="DataToDecrypt">Data do decrypt</param>
        /// <param name="RSAKeyInfo">Used as receiver's private key</param>
        /// <returns>Decrypted data</returns>
        public static byte[]? RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACng RSA = new())
                {
                    //Import the RSA Key information. This needs to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding. OAEP padding is only available on Microsoft Windows XP or later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, RSAEncryptionPadding.OaepSHA256);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }


        /// <summary>
        /// Method used for signing data using RSA
        /// </summary>
        /// <param name="hashedDataToSign">Hashed data to sign</param>
        /// <param name="RSAKeyInfo">Used as sender's private key</param>
        /// <returns>Signed hash</returns>
        public static byte[]? RSASignMessage(byte[] hashedDataToSign, RSAParameters RSAKeyInfo)
        {
            try
            {
                byte[] signedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACng RSA = new())
                {
                    //Import the RSA Key information. This needs to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding. OAEP padding is only available on Microsoft Windows XP or later.  
                    signedData = RSA.SignHash(hashedDataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
                return signedData;
            }
            //Catch and display a CryptographicException to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }


        /// <summary>
        /// Method used for verifying data that was signed and hashed
        /// </summary>
        /// <param name="hashedData">Hashed data to verify</param>
        /// <param name="RSAKeyInfo">Used as sender's public key</param>
        /// <param name="signature">Data signed by sender</param>
        /// <returns>Boolean value of the verification reuslt</returns>
        public static bool RSAVerifyMessage(byte[] hashedData, RSAParameters RSAKeyInfo, byte[] signature)
        {
            try
            {
                bool isDataValid;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACng RSA = new())
                {
                    //Import the RSA Key information. This needs to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding. OAEP padding is only available on Microsoft Windows XP or later.  
                    isDataValid = RSA.VerifyHash(hashedData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
                return isDataValid;
            }
            //Catch and display a CryptographicException to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return false;
            }
        }
    }
}
