using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Diagnostics;

namespace LANCHAT2
{
    public enum Tryb
    {
        Rozgloszeniowy,
        Adresowy,
        Petlowy
    }
    public partial class MainWindow : Window
    {
        private const int Port = 7799;
        private UdpClient udpClient;
        private IPEndPoint localEndPoint;
        string last_message;
        private Tryb tryb = Tryb.Rozgloszeniowy;

        public MainWindow()
        {
            Trace.WriteLine("Start");

            InitializeComponent();
            textBoxIpAddress.IsEnabled = false;
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
                if (tryb == Tryb.Rozgloszeniowy)
                {
                    IPAddress localAdress = NetworkUtils.GetLocalIPAddress();
                    IPAddress ipAddress = NetworkUtils.GetBroadcastAddress(localAdress, NetworkUtils.GetSubnetMask(localAdress));


                    var a = NetworkUtils.GetAllLocalIPAddresses();

                    foreach (var ip in a)
                    {
                        IPAddress ipA = NetworkUtils.GetBroadcastAddress(ip, NetworkUtils.GetSubnetMask(ip));
                        char sekretny_znak = (char)13;
                        byte[] messageBytes = Encoding.UTF8.GetBytes(ip.ToString() + sekretny_znak);
                        byte[] messageBytes2 = Encoding.UTF8.GetBytes(message);
                        byte[] combinedBytes = messageBytes.Concat(messageBytes2).ToArray();
                        udpClient.Send(combinedBytes, combinedBytes.Length, new IPEndPoint(ipA, Port));
                    }
                }

                else if (tryb == Tryb.Adresowy)
                {
                    IPAddress ipaddress = IPAddress.Parse(textBoxIpAddress.Text);
                    textBoxReceivedMessages.AppendText($"Wysłano: {message}\n");
                    char sekretny_znak = (char)13;

                    byte[] messageBytes = Encoding.UTF8.GetBytes(ipaddress.ToString() + sekretny_znak);
                    byte[] messageBytes2 = Encoding.UTF8.GetBytes(message);
                    byte[] combinedBytes = messageBytes.Concat(messageBytes2).ToArray();
                    udpClient.Send(combinedBytes, combinedBytes.Length, new IPEndPoint(ipaddress, Port));
                }
                else if (tryb == Tryb.Petlowy)
                {
                    IPAddress localAdress = NetworkUtils.GetLocalIPAddress();
                    IPAddress ipAddress = NetworkUtils.GetBroadcastAddress(localAdress, NetworkUtils.GetSubnetMask(localAdress));


                    var a = NetworkUtils.GetAllIPAddressesInNetwork(localAdress, NetworkUtils.GetSubnetMask(ip));

                    foreach (var ip in a)
                    {
                        Trace.WriteLine($"{ip} PIERWSZA PETLA");

                        var ipA = NetworkUtils.GetAllIPAddressesInNetwork(ip, NetworkUtils.GetSubnetMask(ip));
                        foreach(var element in ipA)
                        {
                            Trace.WriteLine($"{element} DRUGA PETLA");

                            char sekretny_znak = (char)13;
                            byte[] messageBytes = Encoding.UTF8.GetBytes(ip.ToString() + sekretny_znak);
                            byte[] messageBytes2 = Encoding.UTF8.GetBytes(message);
                            byte[] combinedBytes = messageBytes.Concat(messageBytes2).ToArray();
                            udpClient.Send(combinedBytes, combinedBytes.Length, new IPEndPoint(element, Port));
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show($"Błąd wysyłania wiadomości UDP: {ex.Message}");
            }
        }

        private void buttonSend_Click(object sender, RoutedEventArgs e)
        {
            string message = textBoxMessage.Text;
            if (message != "")
                SendMessage(message, "T");
            else
                MessageBox.Show("Wiadomość nie może być pusta");
        }
        private void btnTryb_Click(object sender, RoutedEventArgs e)
        {
            if (tryb == Tryb.Rozgloszeniowy)
            {
                textBoxIpAddress.IsEnabled = true;
                tryb = Tryb.Adresowy;
                btnTryb.Content = "Tryb Adresowy";
            }
            else if (tryb == Tryb.Adresowy)
            {
                textBoxIpAddress.IsEnabled = false;
                tryb = Tryb.Petlowy;
                btnTryb.Content = "Tryb Pętlowy";
            }
            else if (tryb == Tryb.Petlowy)
            {
                textBoxIpAddress.IsEnabled = false;
                tryb = Tryb.Rozgloszeniowy;
                btnTryb.Content = "Tryb Rozgłoszeniowy";
            }
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
    public static List<IPAddress> GetAllIPAddressesInNetwork(IPAddress ipAddress, IPAddress subnetMask)
    {
        List<IPAddress> ipAddressesInNetwork = new List<IPAddress>();

        byte[] ipBytes = ipAddress.GetAddressBytes();
        byte[] maskBytes = subnetMask.GetAddressBytes();

        if (ipBytes.Length != maskBytes.Length)
        {
            throw new ArgumentException("IP address and subnet mask do not have the same length.");
        }

        byte[] networkBytes = new byte[ipBytes.Length];
        for (int i = 0; i < ipBytes.Length; i++)
        {
            networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
        }

        IPAddress networkAddress = new IPAddress(networkBytes);
        IPAddress broadcastAddress = GetBroadcastAddress(networkAddress, subnetMask);

        uint startIP = BitConverter.ToUInt32(networkAddress.GetAddressBytes(), 0);
        uint endIP = BitConverter.ToUInt32(broadcastAddress.GetAddressBytes(), 0);

        for (uint currentIP = startIP; currentIP <= endIP; currentIP++)
        {
            byte[] bytes = BitConverter.GetBytes(currentIP);
            Array.Reverse(bytes);
            ipAddressesInNetwork.Add(new IPAddress(bytes));
        }

        return ipAddressesInNetwork;
    }

}
