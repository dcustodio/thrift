using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Thrift.Transport
{
    class TSSLSocket : TStreamTransport
    {
           /// <summary>
        /// Internal logger for class
        /// </summary>
        //        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// Internal TCP Client
        /// </summary>
        private TcpClient client = null;

        /// <summary>
        /// Internal SSL Stream for IO
        /// </summary>
        private SslStream sslStream = null;

        /// <summary>
        /// Internal SSL Cert for Socket.  This will be the server or client cert depending on setup.
        /// </summary>
        private X509Certificate certificate;

        /// <summary>
        /// IO Timeout
        /// </summary>
        private int timeout = 10;
        /// <summary>
        /// Server ip
        /// </summary>
        private string host;
        /// <summary>
        /// server port
        /// </summary>
        private int port;

        ///// <summary>
        ///// Initializes a new instance of the TSSLSocket class
        ///// </summary>
        ///// <param name="hostName">Server ip</param>
        ///// <param name="port">Server port</param>
        public TSSLSocket(string hostName, int port)
        {
            this.host = hostName;
            this.port = port;

            this.Setup(hostName, port);
        }


        /// <summary>
        /// Sets Send / Recv Timeout for IO
        /// </summary>
        public int Timeout
        {
            set
            {
                this.client.ReceiveTimeout = this.client.SendTimeout = this.timeout = value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether TCP Client is Cpen 
        /// </summary>
        public override bool IsOpen
        {
            get
            {
                if (this.client == null)
                {
                    return false;
                }

                return this.client.Connected;
            }
        }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }



        /// <summary>
        /// Sets up Socket as an SSL Client
        /// </summary>
        public override void Open()
        {
            if (!this.IsOpen)
            {
                throw new TTransportException(TTransportException.ExceptionType.NotOpen, "Socket Not Open");
            }

            this.Setup(host, port);
        }

        /// <summary>
        /// Closes SSL Socket
        /// </summary>
        public override void Close()
        {
            base.Close();

            if (this.client != null)
            {
                this.client.Close();
                this.client = null;
            }

            if (this.sslStream != null)
            {
                this.sslStream.Close();
                this.sslStream = null;
            }
        }



        /// <summary>
        /// Configures the Socket for SSL
        /// </summary>
        /// <param name="targethost">Host name of Server (used by client). Set to null if confinguring a server</param>
        protected void Setup(string hostName, int port)
        {
            this.client = new TcpClient(hostName, port);

            try
            {
                ////TODO: setup 2 way certificate handshake
                ////X509CertificateCollection clientCertificatecollection = new X509CertificateCollection();
                ////clientCertificatecollection.Add(Certificate);
                ////sslStream.AuthenticateAsClient(targethost, clientCertificatecollection, SslProtocols.Tls, false);

                this.sslStream = new SslStream(this.client.GetStream(), false, ValidateServerCertificate);
                this.sslStream.AuthenticateAsClient(hostName);

                //todo timeout
                //this.sslStream.ReadTimeout = this.timeout;
                //this.sslStream.WriteTimeout = this.timeout;

                this.inputStream = this.sslStream;
                this.outputStream = this.sslStream;
            }
            catch (AuthenticationException e)
            {
                this.sslStream.Close();
                this.client.Close();
            }
        }

        public override int Read(byte[] buf, int off, int len)
        {
            if (sslStream == null)
            {
                throw new TTransportException(TTransportException.ExceptionType.NotOpen, "Cannot read from null inputstream");
            }

            return sslStream.Read(buf, off, len);
        }

        public override void Write(byte[] buf, int off, int len)
        {
            if (sslStream == null)
            {
                throw new TTransportException(TTransportException.ExceptionType.NotOpen, "Cannot write to null outputstream");
            }

            sslStream.Write(buf, off, len);
        }

        public override void Flush()
        {
            if (sslStream == null)
            {
                throw new TTransportException(TTransportException.ExceptionType.NotOpen, "Cannot flush null outputstream");
            }

            sslStream.Flush();
        }

    }
}
