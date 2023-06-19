using System.Security.Cryptography;

namespace CryptographySignalR.Crypto
{
    public class CryptoDH
    {
        private static byte[]? publicKey;

        /// <summary>
        /// Method to get("generate") the public key from object using Diffie-Hellman elliptic curve
        /// </summary>
        /// <param name="diffieHellmanCng">Object's copy to get public key</param>
        /// <returns>Public key</returns>
        public static byte[] DHGenerateKey(ECDiffieHellmanCng diffieHellmanCng)
        {
            publicKey = diffieHellmanCng.PublicKey.ToByteArray();
            return publicKey;
        }


        /// <summary>
        /// Method to create secret key between two users, used for message encryption using Diffie-Hellman elliptic curve
        /// </summary>
        /// <param name="receivedPublicKey">Public key of the second person</param>
        /// <param name="diffieHellmanCng">Object's copy to calculate shared secret with second user (see first param)</param>
        /// <returns>Calculated shared secret</returns>
        public static byte[] DHCalculateSharedSecret(byte[] receivedPublicKey, ECDiffieHellmanCng diffieHellmanCng)
        {
            var receivedDHPublicKey = CngKey.Import(receivedPublicKey, CngKeyBlobFormat.EccPublicBlob);
            var sharedSecret = diffieHellmanCng.DeriveKeyMaterial(receivedDHPublicKey);
            return sharedSecret;
        }
    }
}
