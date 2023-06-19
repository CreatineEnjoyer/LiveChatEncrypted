using Microsoft.AspNetCore.SignalR;

namespace CryptographySignalR.Hubs
{
    public class ChatHub : Hub
    {
        static Dictionary<string, string> userId = new();
        public Task SendMessage(string user, byte[] encryptedMessageRSA, string receiver, byte[] signedMessage, byte[] messageAES)
        {
            foreach (var _user in userId.Keys) 
            {
                if(_user == receiver) 
                    return Clients.All.SendAsync("ReceiveMessage", user, encryptedMessageRSA, true, receiver, signedMessage, messageAES);
            }
            return Clients.All.SendAsync("ReceiveMessage", user, encryptedMessageRSA, false, receiver, signedMessage, messageAES);
        }


        public Task SendPublicKey(string user, string publicKeyDH, string publicKeyRSA, string receiver)
        {
            if (!userId.ContainsKey(user))
                userId.Add(user, Context.ConnectionId);

            return Clients.All.SendAsync("ReceivePublicKey", user, publicKeyDH, publicKeyRSA, receiver);
        }
    }
}
