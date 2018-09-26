using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Sniffer
{
    static class Program
    {
        static void Main(string[] args)
        {

            //Listen to only IPv4 interfaces
            var IPv4Addresses = Dns.GetHostEntry(Dns.GetHostName())
                .AddressList.Where(al => al.AddressFamily == AddressFamily.InterNetwork)
                .AsEnumerable();

            //print some kind of header
            Console.WriteLine("Protocol\tSourceIP:Port\t===>\tDestinationIP:Port");

            //start sniffing for each interface
            foreach(IPAddress ip in IPv4Addresses)
            {
                Sniff(ip);
            }

            //wait for what?
            Console.Read();
        }

        static void Sniff(IPAddress ip)
        {
            //setup the socket to listen on
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            sock.Bind(new IPEndPoint(ip, 0));
            sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            sock.IOControl(IOControlCode.ReceiveAll, new byte[4] { 1, 0, 0, 0 }, null);

            //byte array to save packet data
            //24 bytes for IP header
            byte[] buffer = new byte[24];

            //Async on that
            Action<IAsyncResult> OnReceive = null;
            OnReceive = (ar) =>
            {
                Console.WriteLine("{0}\t{1}:{2}\t===>\t{3}:{4}",
                    buffer.Skip(9).First().ToProtocolString()
                    , new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString()
                    , ((ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 20))).ToString()
                    , new IPAddress(BitConverter.ToUInt32(buffer, 16)).ToString()
                    , ((ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, 22))).ToString());
                buffer = new byte[24];
               
            };

            sock.BeginReceive(buffer, 0, 24, SocketFlags.None, new AsyncCallback(OnReceive), null);

        }

        public static string ToProtocolString(this byte b)
        {
            switch (b)
            {
                case 1: return "ICMP";
                case 6: return "TCP";
                case 17: return "UDP";
                default: return "#" + b.ToString();
            }
        }
    }
}
