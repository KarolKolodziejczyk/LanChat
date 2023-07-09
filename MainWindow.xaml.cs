using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace LANCHAT2
{
    public enum Tryb
    {
        Rozgloszeniowy,
        Adresowy,
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

            InitializeComponent();

            textBoxIpAddress.IsEnabled = false;
            udpClient = new UdpClient();
            localEndPoint = new IPEndPoint(IPAddress.Any, Port);
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
                    byte[] encryptedBytes = result.Buffer;

                    string decryptedMessage = EncryptionHelper.Decrypt(Encoding.UTF8.GetString(encryptedBytes));


                    string[] t = decryptedMessage.Split((char)13, StringSplitOptions.RemoveEmptyEntries);
                    if (last_message != t[1])
                    {
                        var testIP = NetworkUtils.GetAllLocalIPAddresses();
                        foreach (var e in testIP)
                        {

                            if (e.ToString() == t[0])
                            {
                                String test ="(Ja)";
                                t[0] += test;                           
                                break;
                            }
                        }
                        string formattedMessage = $"{t[0]}:\n{t[1]}\n";
                        Dispatcher.Invoke(() => textBoxReceivedMessages.AppendText(formattedMessage));
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
                        IPAddress broadcastAddress = NetworkUtils.GetBroadcastAddress(ip, NetworkUtils.GetSubnetMask(ip));
                        string formattedMessage = $"{ip.ToString()}{(char)13}{message}";
                        byte[] encryptedBytes = Encoding.UTF8.GetBytes(EncryptionHelper.Encrypt(formattedMessage));
                        udpClient.Send(encryptedBytes, encryptedBytes.Length, new IPEndPoint(broadcastAddress, Port));
                    }
                }

                else if (tryb == Tryb.Adresowy)
                {
                    IPAddress ipaddress = IPAddress.Parse(textBoxIpAddress.Text);
                    IPAddress ipHOST = NetworkUtils.GetLocalIPAddress();
                    if(last_message != message)
                        textBoxReceivedMessages.AppendText($"(Ja): {message}\n");
                    IPAddress broadcastAddress = NetworkUtils.GetBroadcastAddress(ipaddress, NetworkUtils.GetSubnetMask(ipaddress));
                    string formattedMessage = $"{NetworkUtils.GetLocalIPAddress()}{(char)13}{message}";
                    byte[] encryptedBytes = Encoding.UTF8.GetBytes(EncryptionHelper.Encrypt(formattedMessage));
                    udpClient.Send(encryptedBytes, encryptedBytes.Length, new IPEndPoint(ipaddress, Port));


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
            textBoxMessage.Text = "";
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
                button_scan.IsEnabled = true;
                Lst_IPs.IsEnabled = true;
                tryb = Tryb.Adresowy;
                btnTryb.Content = "Tryb Adresowy";
            }
            else if (tryb == Tryb.Adresowy)
            {
                textBoxIpAddress.IsEnabled = false;
                button_scan.IsEnabled = false;
                Lst_IPs.IsEnabled = false;
                tryb = Tryb.Rozgloszeniowy;
                btnTryb.Content = "Tryb Rozgłoszeniowy";
            }
        }

        private async void button_scan_Click(object sender, RoutedEventArgs e)
        {
            Lst_IPs.Items.Clear();
            button_scan.IsEnabled = false;
            button_scan.Content = "Skanowanie...";

            try
            {
                var progress = new Progress<int>(count =>
                {
                    button_scan.Dispatcher.Invoke(() =>
                    {
                        button_scan.Content = $"Skanuje...{count.ToString()}";
                    });
                });
                var pingableIPs = await NetworkScanner.ScanNetworkAsync(progress);

                foreach (var ip in pingableIPs)
                {
                    Lst_IPs.Items.Add(ip);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Wystąpił błąd podczas skanowania: {ex.Message}");
            }
            finally
            {
                button_scan.Dispatcher.Invoke(() =>
                {
                    button_scan.IsEnabled = true;
                    button_scan.Content = "Skanuj";
                });
            }
        }


        private void Lst_IPs_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            textBoxIpAddress.Text = Lst_IPs.SelectedItem.ToString();
        }

        private void textBoxReceivedMessages_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {

        }
    }
}