using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Net;
using System.Net.Sockets;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.Net.NetworkInformation;

namespace LANCHAT2
{
    public partial class MainWindow : Window
    {
        private const int Port = 7799;
        private UdpClient udpClient;
        private IPEndPoint localEndPoint;
        string last_message;
        public MainWindow()
        {
            InitializeComponent();

            udpClient = new UdpClient();
            localEndPoint = new IPEndPoint(IPAddress.Any, Port);
         
            //MessageBox.Show(NetworkUtils.GetLocalIPAddress().ToString());
            //MessageBox.Show(NetworkUtils.GetSubnetMask(NetworkUtils.GetLocalIPAddress()));

            StartListening();
        }

        private async void StartListening()
        {
            try
            {
                udpClient.Client.Bind(localEndPoint);
                while (true)
                {
                    UdpReceiveResult result = await udpClient.ReceiveAsync();
                    string receivedMessage = Encoding.UTF8.GetString(result.Buffer);
                    string[] t= Encoding.UTF8.GetString(result.Buffer).Split((char)13, StringSplitOptions.RemoveEmptyEntries); 
                    if (last_message != t[1])
                    {
                        var testIP = NetworkUtils.GetAllLocalIPAddresses();
                        foreach (var e in testIP)
                            if (e.ToString() == t[0]) t[0] += "(Ja)";
                        Dispatcher.Invoke(() => textBoxReceivedMessages.AppendText($"{t[0]}:\n{t[1]}\n"));
                        last_message = t[1];
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Błąd odbierania wiadomości UDP: {ex.Message}");
            }
        }

        private void SendMessage(string message, string ipAddressString)
        {
            try
            {
                IPAddress localAdress = NetworkUtils.GetLocalIPAddress();
                IPAddress ipAddress = NetworkUtils.GetBroadcastAddress(localAdress, NetworkUtils.GetSubnetMask(localAdress));
                  

                var a = NetworkUtils.GetAllLocalIPAddresses();

                foreach (var ip in a)
                {
                    IPAddress ipA = NetworkUtils.GetBroadcastAddress(ip, NetworkUtils.GetSubnetMask(ip));
                    char sekretny_znak = (char)13;
                    byte[] messageBytes = Encoding.UTF8.GetBytes(ip.ToString() + sekretny_znak );
                    byte[] messageBytes2 = Encoding.UTF8.GetBytes(message);
                    byte[] combinedBytes = messageBytes.Concat(messageBytes2).ToArray();
                    udpClient.Send(combinedBytes, combinedBytes.Length, new IPEndPoint(ipA, Port));
                }
                
                //textBoxReceivedMessages.AppendText($"Wysłano: {message}\n");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Błąd wysyłania wiadomości UDP: {ex.Message}");
            }
        }

        private void buttonSend_Click(object sender, RoutedEventArgs e)
        {
            string message = textBoxMessage.Text;
            string ipAddress = textBoxIpAddress.Text;
            SendMessage(message, ipAddress);
        }
    }
}

//Pomocowa Klasa zajmująca się podstawymi zagadnieniami Networkowymi
public static class NetworkUtils
{
    public static IPAddress GetLocalIPAddress()
    {
        string hostName = Dns.GetHostName();
        IPHostEntry hostEntry = Dns.GetHostEntry(hostName);

        foreach (IPAddress address in hostEntry.AddressList)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return address;
            }
        }

        return IPAddress.None;
    }
    public static IPAddress GetSubnetMask(IPAddress ipAddress)
    {
        if (ipAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Adres IP musi być typu IPv4.");
        }

        uint ipAddressValue = BitConverter.ToUInt32(ipAddress.GetAddressBytes(), 0);
        uint subnetMaskValue = 0xFFFFFFFF << (32 - ipAddress.GetAddressBytes()[2]);

        byte[] subnetMaskBytes = BitConverter.GetBytes(subnetMaskValue);
        Array.Reverse(subnetMaskBytes);

        IPAddress subnetMask = new IPAddress(subnetMaskBytes);
        return subnetMask;
    }
    public static IPAddress GetBroadcastAddress(IPAddress ipAddress, IPAddress subnetMask)
    {
        byte[] ipBytes = ipAddress.GetAddressBytes();
        byte[] maskBytes = subnetMask.GetAddressBytes();

        if (ipBytes.Length != maskBytes.Length)
        {
            throw new ArgumentException("IP address and subnet mask do not have the same length.");
        }

        byte[] broadcastBytes = new byte[ipBytes.Length];
        for (int i = 0; i < ipBytes.Length; i++)
        {
            broadcastBytes[i] = (byte)(ipBytes[i] | (byte)~maskBytes[i]);
        }

        return new IPAddress(broadcastBytes);
    }
    public static List<IPAddress> GetAllLocalIPAddresses()
    {
        List<IPAddress> ipAddresses = new List<IPAddress>();

        NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
        foreach (NetworkInterface networkInterface in networkInterfaces)
        {
            if (networkInterface.OperationalStatus == OperationalStatus.Up)
            {
                IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
                foreach (UnicastIPAddressInformation ipAddressInfo in ipProperties.UnicastAddresses)
                {
                    if (ipAddressInfo.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        ipAddresses.Add(ipAddressInfo.Address);
                    }
                }
            }
        }

        return ipAddresses;
    }
}
