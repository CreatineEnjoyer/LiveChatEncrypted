using System.Security.Cryptography;

namespace CryptographySignalR.Crypto
{
    public class CryptoSHA
    {
        /// <summary>
        /// Method used for hashing data using SHA256
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Computed hash for data</returns>
        public static byte[] SHA256HashData(byte[] data)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedData = sha256.ComputeHash(data);
                return hashedData;
            }
        }

        /// <summary>
        /// Method used for hashing data using SHA512
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Computed hash for data</returns>
        public static byte[] SHA512HashData(byte[] data)
        {
            using (var sha512 = SHA512.Create())
            {
                var hashedData = sha512.ComputeHash(data);
                return hashedData;
            }
        }

        /// <summary>
        /// Method used for hashing data using SHA1
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Computed hash for data</returns>
        public static byte[] SHA1HashData(byte[] data)
        {
            using (var sha1 = SHA1.Create())
            {
                var hashedData = sha1.ComputeHash(data);
                return hashedData;
            }
        }
    }
}
