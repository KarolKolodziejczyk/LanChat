using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;


namespace LANCHAT2
{

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

}
