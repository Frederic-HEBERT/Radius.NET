using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Radius.Attributes;
using Radius.Enum;
using Radius.Utils;

namespace Radius
{
    public class RadiusClient
    {
        #region Constants
        private const int DEFAULT_RETRIES = 3;
        private const uint DEFAULT_AUTH_PORT = 1812;
        private const uint DEFAULT_ACCT_PORT = 1813;
        private const int DEFAULT_SOCKET_TIMEOUT = 3000;
        #endregion

        #region Private
        private string _sharedSecret = String.Empty;
        private string _hostName = String.Empty;
        private uint _authPort = DEFAULT_AUTH_PORT;
        private uint _acctPort = DEFAULT_ACCT_PORT;
        private uint _authRetries = DEFAULT_RETRIES;
        private uint _acctRetries = DEFAULT_RETRIES;
        private int _socketTimeout = DEFAULT_SOCKET_TIMEOUT;
        private IPEndPoint _localEndPoint;
        #endregion

        #region Properties
        public int SocketTimeout
        {
            get { return _socketTimeout; }
            set { _socketTimeout = value; }
        }
        #endregion

        #region Constructors
        public RadiusClient(string hostName, string sharedSecret,
                            int sockTimeout = DEFAULT_SOCKET_TIMEOUT,
                            uint authPort = DEFAULT_AUTH_PORT,
                            uint acctPort = DEFAULT_ACCT_PORT,
                            IPEndPoint localEndPoint = null)
        {
            _hostName = hostName;
            _authPort = authPort;
            _acctPort = acctPort;
            _localEndPoint = localEndPoint;
            _sharedSecret = sharedSecret;
            _socketTimeout = sockTimeout;
        }
        #endregion

        #region Public Methods
        public RadiusPacket Authenticate(string username, string password)
        {
            RadiusPacket packet = new RadiusPacket(RadiusCode.ACCESS_REQUEST);
            packet.SetAuthenticator();
            byte[] encryptedPass = RadiusUtils.EncodePapPassword(Encoding.ASCII.GetBytes(password), packet.Authenticator, _sharedSecret);
            packet.SetAttribute(new RadiusAttribute(RadiusAttributeType.USER_NAME, Encoding.ASCII.GetBytes(username)));
            packet.SetAttribute(new RadiusAttribute(RadiusAttributeType.USER_PASSWORD, encryptedPass));
            return packet;
        }

        public async Task<RadiusPacket> SendAndReceivePacket(RadiusPacket packet, int retries = DEFAULT_RETRIES)
        {
            using (UdpClient udpClient = new())
            {
                udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, _socketTimeout);

                IPAddress hostIP = null;

                try
                {
                    // Starting with Vista, we are able to bind to a local endpoint to guarantee the packet
                    // will be sent out a particular interface
                    // This is explained in the following blog
                    // http://blogs.technet.com/b/networking/archive/2009/04/25/source-ip-address-selection-on-a-multi-homed-windows-computer.aspx
                    if (_localEndPoint != null)
                        udpClient.Client.Bind(_localEndPoint);

                    if (!IPAddress.TryParse(_hostName, out hostIP))
                    {
                        //Try performing a DNS lookup
                        var host = Dns.GetHostEntry(_hostName);
                        hostIP = host.AddressList.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                        if (hostIP == null)
                            throw new Exception("Resolving " + _hostName + " returned no hits in DNS");

                    }
                }
                catch (SocketException e)
                {
                    int hr = Marshal.GetHRForException(e);
                    string hexValue = hr.ToString("X");

                    //The requested name is valid, but no data of the requested type was found
                    if (hexValue == "80004005")
                        return null;
                }

                var destinationPort = packet.PacketType == RadiusCode.ACCOUNTING_REQUEST || packet.PacketType == RadiusCode.ACCOUNTING_RESPONSE ? _acctPort : _authPort;

                var endPoint = new IPEndPoint(hostIP, (int)destinationPort);
                int numberOfAttempts = 0;

                do
                {
                    try
                    {
                        await udpClient.SendAsync(packet.RawData, packet.RawData.Length, endPoint);

                        // Using the synchronous method for the timeout features
                        var result = udpClient.Receive(ref endPoint);
                        RadiusPacket receivedPacket = new RadiusPacket(result);
                        if (receivedPacket.Valid && VerifyAuthenticator(packet, receivedPacket))
                            return receivedPacket;
                    }
                    catch (SocketException)
                    {
                        //Server isn't responding
                    }

                    numberOfAttempts++;

                } while (numberOfAttempts < retries);
            }

            return null;
        }

        /// <summary>
        /// Sends a Server-Status packet using the shared secret of the client
        /// </summary>
        /// <returns></returns>
        public async Task<RadiusPacket> Ping()
        {
            // Create a new RADIUS packet with the Server-Status code
            RadiusPacket authPacket = new RadiusPacket(RadiusCode.SERVER_STATUS);
            // Populate the Request-Authenticator
            authPacket.SetAuthenticator(_sharedSecret);
            // Add the Message-Authenticator as a last step.  Note: Server-Status packets don't require any other attributes
            authPacket.SetMessageAuthenticator(_sharedSecret);
            // We MUST NOT retransmit Server-Status packets according to https://tools.ietf.org/html/rfc5997
            return await SendAndReceivePacket(authPacket, 0);
        }
        #endregion

        #region Private Methods
        public bool VerifyAuthenticator(RadiusPacket requestedPacket, RadiusPacket receivedPacket)
        {
            return requestedPacket.Identifier == receivedPacket.Identifier
                && receivedPacket.Authenticator.SequenceEqual(RadiusUtils.ResponseAuthenticator(receivedPacket.RawData, requestedPacket.Authenticator, _sharedSecret));
        }

        public static bool VerifyAccountingAuthenticator(byte[] radiusPacket, string secret)
        {
            var secretBytes = Encoding.ASCII.GetBytes(secret);

            byte[] sum = new byte[radiusPacket.Length + secretBytes.Length];

            byte[] authenticator = new byte[16];
            Array.Copy(radiusPacket, 4, authenticator, 0, 16);

            Array.Copy(radiusPacket, 0, sum, 0, radiusPacket.Length);
            Array.Copy(secretBytes, 0, sum, radiusPacket.Length, secretBytes.Length);
            Array.Clear(sum, 4, 16);

            var hash = MD5.HashData(sum.AsSpan(0, sum.Length));
            return authenticator.SequenceEqual(hash);
        }
        #endregion
    }
}