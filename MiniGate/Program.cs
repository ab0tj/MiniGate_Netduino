using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.IO;
using System.IO.Ports;
using System.Text;
using Microsoft.SPOT;
using Microsoft.SPOT.Net.NetworkInformation;
using Microsoft.SPOT.Hardware;
using SecretLabs.NETMF.Hardware;
using SecretLabs.NETMF.Hardware.NetduinoPlus;

namespace MiniGate
{
    public class Main
    {
        public static string Callsign;
        public static string SSID;

        public static void Main()
        {
            Thread ledControl = new Thread(new ThreadStart(LEDControl.Main));
            ledControl.Start();
            Config.Init();
            Callsign = Config.Read("stn.callsign");
            SSID = Config.Read("stn.ssid");
            Packet.OpenPort();
            NetworkInterface[] eth = NetworkInterface.GetAllNetworkInterfaces();
            Debug.Print("IP: " + eth[0].IPAddress);     // TODO: Remove for final version
            Thread telnet = new Thread(new ThreadStart(TelnetServer.Main));
            telnet.Start();
            Thread.Sleep(Timeout.Infinite);
            LEDControl.errors--;    // Clear the boot error
        }
    }

    public class Config
    {
        static DirectoryInfo ConfigFolder = new DirectoryInfo(@"\SD\MiniGate\Config\");

        public static void Init()
        {
            LEDControl.errors++;
            while (!ConfigFolder.Exists)
            {
                try
                {
                    ConfigFolder.Create();
                }
                catch
                {
                    Thread.Sleep(1000);
                }
            }
            LEDControl.errors--;
        }

        public static string Read(string file)
        {
            if (!ConfigFolder.Exists) Init();
            FileInfo ConfigFile = new FileInfo(@"\SD\MiniGate\Config\" + file);
            if (ConfigFile.Exists) return new String(Encoding.UTF8.GetChars(File.ReadAllBytes(@"\SD\MiniGate\Config\" + file)));
            return null;
        }

        public static void Write(string file, string val)
        {
            if (!ConfigFolder.Exists) Init();
            File.WriteAllBytes(@"\SD\MiniGate\Config\" + file, Encoding.UTF8.GetBytes(val));
        }
    }

    public class Packet
    {
        static SerialPort modem = new SerialPort("COM2", 9600, Parity.None, 8, StopBits.One);
        static int bytes = 0;
        static byte[] indata = new byte[1024];
        static bool esc = false;

        public static void OpenPort()
        {
            modem.DataReceived += new SerialDataReceivedEventHandler(modem_DataReceived); // Handler for incoming serial data
            modem.Open();
        }

        private static void modem_DataReceived(object sender, SerialDataReceivedEventArgs e)
        {
            byte[] inbyte = new byte[1];
            while (modem.BytesToRead > 0)
            {
                modem.Read(inbyte, 0, 1);       // Grab the data one byte at a time.
                if (bytes > 1022) bytes = 0;    // (Input buffer is only 1024 bytes)
                if (esc)
                {
                    esc = false;
                    if (inbyte[0] == 0x7E)     // If this was an escaped flag byte
                    {
                        Parse();
                    }
                    else
                    {
                        indata[bytes++] = inbyte[0];       // If not, just add the escaped byte to the buffer
                    }
                }
                else
                {
                    if (inbyte[0] == 0x1B)     // If this was an escape byte
                    {
                        esc = true;
                    }
                    else
                    {
                        indata[bytes++] = inbyte[0];       // If not, just add this byte to the buffer
                    }
                }
            }
        }

        private static void Parse()   // Where most of the packet decoding magic happens
        {
            if (bytes > 17)    // If the packet is less than 18 bytes, it's obviously broken, so don't even bother.
            {
                ushort CalcFCS = 0xFFFF;   // We will check the FCS before going on

                for (int i = 0; i < (bytes - 2); i++)   // Loop thru all bytes in the packet except the FCS field
                {
                    byte inbyte = indata[i];
                    for (int k = 0; k < 8; k++)     // Loop thru all 8 bits in this byte
                    {
                        bool inbit = ((inbyte & 0x01) == 0x01);      // Grab the LSB of the current byte
                        bool fcsbit = ((CalcFCS & 0x0001) == 0x0001);   // Grab the LSB of the current FCS value
                        CalcFCS >>= 1;                                  // Shift the current FCS value one bit right
                        if (fcsbit != inbit) CalcFCS = (ushort)(CalcFCS ^ 0x8408);      // If the LSB of this byte and the bit that was shifted off the FCS don't match, XOR the FCS with 0x8408
                        inbyte >>= 1;        // Shift this byte right to get ready for the next bit
                    }
                }
                CalcFCS = (ushort)(CalcFCS ^ 0xFFFF);      // XOR The FCS with 0xFFFF

                if ((indata[bytes - 1] == (CalcFCS >> 8)) && (indata[bytes - 2] == (CalcFCS & 0xFF)))
                {
                    int NumCalls = 0;
                    byte[][] Callsigns = new byte[10][];
                    byte[] SSIDs = new byte[10];
                    bool[] HBit = new bool[10];
                    string Via = "";

                    for (int i = 0; i <= 9; i++)
                    {
                        Callsigns[i] = new byte[6];     // Initialize "jagged" callsign array
                    }

                    for (int a = 0; a <= 9; a++)    // Loop through up to 10 callsigns in the address field
                    {
                        NumCalls++;

                        for (int i = 0; i <= 5; i++)
                        {
                            Callsigns[a][i] = (byte)(indata[((a * 7) + i)] >> 1);   // Get the byte for each letter of this call, and shift it right one bit
                        }

                        SSIDs[a] = (byte)((indata[((a + 1) * 7) - 1] & 0x1E) >> 1);     // Get the SSID of this call (bits 4-1 of the last octect of this call)
                        HBit[a] = ((indata[((a + 1) * 7) - 1] & 0x80) == 0x80);     // See if the "H bit" of this SSID octet is set (indicates if this digi slot has been used)

                        if ((indata[((a + 1) * 7) - 1] & 0x01) == 0x01) break;      // Exit the loop if this is the last call in the address field
                    }

                    if ((indata[NumCalls * 7] == 0x03) && (indata[(NumCalls * 7) + 1] == 0xF0))     // Don't bother going on if this isn't a UI packet
                    {                                                                               // We'd check this sooner, but need to know where these bytes are in the packet first
                        if (NumCalls > 2)
                        {
                            Via = ",";
                            for (int i = 2; i < NumCalls; i++)
                            {
                                string Callsign = new String(UTF8Encoding.UTF8.GetChars(Callsigns[i]));
                                Via = Via + Callsign.Trim();
                                if (SSIDs[i] != 0x00) Via = Via + "-" + SSIDs[i].ToString();    // Only add the SSID if it's not zero
                                if (HBit[i]) Via = Via + "*";   // Add a "*" if this digi slot has been used
                                if ((i + 1) < NumCalls) Via = Via + ",";    // Add a "," if there are more digi's in the list
                            }
                        }
                        string Source = new String(UTF8Encoding.UTF8.GetChars(Callsigns[1]));
                        Source = Source.Trim();
                        if (SSIDs[1] != 0x00) Source = Source + "-" + SSIDs[1].ToString();
                        string Dest = new String(UTF8Encoding.UTF8.GetChars(Callsigns[0]));
                        Dest = Dest.Trim();
                        if (SSIDs[0] != 0x00) Dest = Dest + "-" + SSIDs[0].ToString();
                        string Payload = new String(UTF8Encoding.UTF8.GetChars(Utility.ExtractRangeFromArray(indata, (NumCalls * 7) + 2, bytes - (NumCalls * 7) - 4)));
                        Debug.Print(Source + ">" + Dest + Via + ":" + Payload);
                        if (TelnetServer.RFMonEnable) TelnetServer.SendData(Source + ">" + Dest + Via + ":" + Payload + "\n\r");
                    }
                }
            }
            Array.Clear(indata, 0, bytes + 1);
            bytes = 0;
        }
    }

    public class LEDControl
    {
        public static int errors = 1;     // Start with one "error" to show booting

        public static void Main()
        {
            OutputPort led = new OutputPort(Pins.ONBOARD_LED, false);
            while (true)
            {
                led.Write(true);
                if (errors == 0) Thread.Sleep(1400);
                Thread.Sleep(100);
                led.Write(false);
                if (errors == 0) Thread.Sleep(1400);
                Thread.Sleep(100);
            }
        }
    }

    public class TelnetServer
    {
        public static Socket Connection = null;
        public static bool RFMonEnable = false;

        public static void Main()
        {
            Socket telnetSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            telnetSock.Bind(new IPEndPoint(IPAddress.Any, 23));
            telnetSock.Listen(1);

            while (true)
            {
                Connection = telnetSock.Accept();
                ConfigMenu();
                Connection.Close();
                RFMonEnable = false;
            }
        }

        static string GetInput()
        {
            byte[] RXData = new byte[Connection.Available];
            Connection.Receive(RXData);
            Connection.Poll(-1, SelectMode.SelectRead);
            RXData = new byte[Connection.Available];
            Connection.Receive(RXData);
            try
            {
                return new String(Encoding.UTF8.GetChars(RXData)).Trim();       // TODO: Replace ugly hack with real input validation
            }
            catch
            {
                return null;
            }
        }

        static void ConfigMenu()
        {
            while (true)
            {
                SendData("\n\rMiniGate Console\n\n\r 1) RF Port Config\n\r 2) Digipeater Config\n\r 3) Network Config\n\r 4) Monitor RF Port\n\r 5) Disconnect\n\n\rEnter an option: ");
                switch (GetInput())
                {
                    case "1":
                        RFConfig();
                        break;
                    case "2":
                        DigiConfig();
                        break;
                    case "3":
                        NetworkConfig();
                        break;
                    case "4":
                        MonitorRF();
                        break;
                    case "5":
                        return;
                    default:
                        break;
                }
            }
        }

        public static void SendData(string TXData)
        {
            byte[] senddata = UTF8Encoding.UTF8.GetBytes(TXData);
            Connection.Send(senddata, SocketFlags.None);
        }

        static void RFConfig()
        {
        }

        static void DigiConfig()
        {
        }

        static void NetworkConfig()
        {
        }

        static void MonitorRF()
        {
            SendData("\n\rEntering monitor mode. Press <enter> to exit.\n\n\r");
            RFMonEnable = true;
            GetInput();
            RFMonEnable = false;
        }
    }

    public class APRSIS
    {
        public static Socket Connection = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        public static bool IsConnected = false;
        static string Server;
        static int Port;

        public static void Main()
        {
            Server = Config.Read("aprsis.server");
            Port = int.Parse(Config.Read("aprsis.port"));

            while (true)
            {
                LEDControl.errors++;
                EndPoint APRSISServer = new IPEndPoint(Dns.GetHostEntry(Server).AddressList[0], Port);
                try
                {
                    Connection.Connect(APRSISServer);
                    IsConnected = true;
                    LEDControl.errors--;
                }
                catch
                {
                    Thread.Sleep(10000);
                }
                // TODO: APRS-IS Client code goes here.
            }
        }
    }
}