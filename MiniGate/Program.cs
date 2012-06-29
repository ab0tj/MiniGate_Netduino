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
    public class MiniGate
    {
        public const string MiniGateVer = "Test";
        public const string MiniGateDest = "APMG01";
        public static string Callsign;
        public static int SSID = 0;
        public static string FullCall;
        public static NetworkInterface[] eth;

        public static void Main()
        {
            Thread ledControl = new Thread(new ThreadStart(LEDControl.Main));
            ledControl.Start();
            Config.Init();
            Callsign = Config.Read("stn.callsign");
            FullCall = Callsign;
            try
            {
                SSID = int.Parse(Config.Read("stn.ssid"));
            }
            catch { }
            if (SSID != 0) FullCall += "-" + SSID.ToString();
            Packet.OpenPort();
            eth = NetworkInterface.GetAllNetworkInterfaces();
            Debug.Print("IP: " + eth[0].IPAddress);     // TODO: Remove for final version
            Thread telnet = new Thread(new ThreadStart(TelnetServer.Main));
            telnet.Start();
            Thread aprsis = new Thread(new ThreadStart(APRSIS.Main));
            aprsis.Start();
            Thread beacon = new Thread(new ThreadStart(Beacon.Main));
            beacon.Start();
            LEDControl.errors--;    // Clear the boot error
            Thread.Sleep(Timeout.Infinite);
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
            return "";
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
                        string Payload = string.Empty;      // (only necessary because of try/catch block below)
                        try
                        {
                            Payload = new String(UTF8Encoding.UTF8.GetChars(indata, (NumCalls * 7) + 2, bytes - (NumCalls * 7) - 4));
                        }
                        catch 
                        {
                            Debug.Print("Failed to decode packet payload into string!");
                            Array.Clear(indata, 0, bytes + 1);          // TODO: Find out why the line above throws exceptions somtimes
                            bytes = 0;
                            return;
                        }
                        if (Via.IndexOf("TCPIP") == -1 && Via.IndexOf("TCPXX") == -1) APRSIS.SendData(Source + ">" + Dest + Via + ",qAR," + MiniGate.FullCall + ":" + Payload + "\r\n");
                        if (TelnetServer.RFMonEnable) TelnetServer.SendData(Source + ">" + Dest + Via + ":" + Payload + "\r\n");
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
        static string Pass;

        public static void Main()
        {
            Pass = Config.Read("telnet.pass");
            Socket telnetSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            telnetSock.Bind(new IPEndPoint(IPAddress.Any, 23));
            telnetSock.Listen(1);

            while (true)
            {
                try
                {
                    using (Connection = telnetSock.Accept())
                    {
                        SendData("Password: ");
                        if (GetInput() == Pass) ConfigPrompt();
                        Connection.Close();
                    }
                }
                catch
                {
                    Thread.Sleep(1000);
                }
                RFMonEnable = false;
            }
        }

        static bool IsConnected()
        {
            try
            {
                return !(Connection.Poll(1000, SelectMode.SelectRead) && (Connection.Available == 0));
            }
            catch
            {
                return false;
            }
        }

        static string GetInput()
        {
            if (!IsConnected()) return "";
            try
            {
                byte[] RXData = new byte[Connection.Available];
                Connection.Receive(RXData);
                Connection.Poll(-1, SelectMode.SelectRead);
                RXData = new byte[Connection.Available];
                Connection.Receive(RXData);
                return new String(Encoding.UTF8.GetChars(RXData)).Trim();       // TODO: Replace ugly hack with real input validation
            }
            catch
            {
                return "";
            }
        }

        static void ConfigPrompt()
        {
            SendData("\r\nMiniGate Console\n\r\n");
            while (IsConnected())
            {
                SendData("cmd: ");
                string InFull = GetInput();
                string[] InCmd = InFull.Split(' ');
                switch (InCmd[0].ToUpper())
                {
                    case "QUIT":
                    case "EXIT":
                        return;
                    case "DISP":
                        // Display code goes here
                        break;
                    case "MON":
                    case "MONITOR":
                        if (InCmd.Length == 2)
                        {
                            RFMon(InCmd[1].ToUpper());
                        }
                        else
                        {
                            SendData("?\r\n");
                        }
                        break;
                    case "MYCALL":
                        if (InCmd.Length > 1)
                        {
                            ChangeCall(InCmd[1]);
                            break;
                        }
                        SendData(MiniGate.FullCall + "\r\n");
                        break;
                    case "APRSSRV":
                        if (InCmd.Length > 1)
                        {
                            ChangeAPRSSrv(InCmd[1]);
                            break;
                        }
                        SendData(APRSIS.Server + ":" + APRSIS.Port + "\r\n");
                        break;
                    case "APRSPASS":
                        if (InCmd.Length == 2)
                        {
                            try
                            {
                                APRSIS.Pass = int.Parse(InCmd[1]);
                                Config.Write("aprsis.pass", InCmd[1]);
                                break;
                            }
                            catch { }
                        }
                        if (InCmd.Length == 1)
                        {
                            SendData(APRSIS.Pass + "\r\n");
                            break;
                        }
                        SendData("?\r\n");
                        break;
                    case "DHCP":

                    case "MYIP":

                    case "DNSSRV":

                    case "TXDELAY":
                        
                    case "PASSWD":
                        if (InCmd.Length > 1)
                        {
                            Config.Write("telnet.pass", InFull.Substring(InCmd[0].Length + 1));
                            TelnetServer.Pass = InFull.Substring(InCmd[0].Length + 1);
                            break;
                        }
                        SendData("?\r\n");
                        break;
                    case "BTEXT":
                        if (InCmd.Length > 1)
                        {
                            Config.Write("stn.btext", InFull.Substring(InCmd[0].Length + 1));
                            Beacon.BText = InFull.Substring(InCmd[0].Length + 1);
                            break;
                        }
                        SendData(Beacon.BText + "\r\n");
                        break;
                    case "BINT":
                    case "BINTERVAL":
                        if (InCmd.Length == 2)
                        {
                            try
                            {
                                Beacon.Interval = int.Parse(InCmd[1]);
                                Config.Write("stn.binterval", InCmd[1]);
                                break;
                            }
                            catch
                            {}
                        }
                        if (InCmd.Length == 1)
                        {
                            SendData(Beacon.Interval.ToString() + "\r\n");
                            break;
                        }
                        SendData("?\r\n");
                        break;
                    case "PATH":
                    default:
                        SendData("?\r\n");
                        break;
                }
            }
        }

        public static void SendData(string TXData)
        {
            if (!IsConnected()) return;
            try
            {
                Connection.Send(UTF8Encoding.UTF8.GetBytes(TXData), SocketFlags.None);
            }
            catch { }
        }

        public static void RFMon(string param)
        {
            switch (param)
            {
                case "ON":
                    RFMonEnable = true;
                    break;
                case "OFF":
                    RFMonEnable = false;
                    break;
                default:
                    SendData("?\r\n");
                    break;
            }
        }

        public static void ChangeCall(string newcall)
        {
            string[] split = newcall.Split('-');
            int ssid = 0;
            if (split[0].Length > 6)
            {
                SendData("Callsign must be 6 characters or less.\r\n");
                return;
            }
            try
            {
                ssid = int.Parse(split[1]);
            }
            catch { }
            if (ssid > 15)
            {
                SendData("SSID must be between 0 and 15.\r\n");
                return;
            }
            Config.Write("stn.callsign", split[0].ToUpper());
            MiniGate.Callsign = split[0].ToUpper();
            Config.Write("stn.ssid", ssid.ToString());
            MiniGate.SSID = ssid;
        }

        public static void ChangeAPRSSrv(string srv)
        {
            string[] split = srv.Split(':');
            int port = 14580;
            try
            {
                port = int.Parse(split[1]);
            }
            catch { }
            if (port > 65535)
            {
                SendData("Port must be between 0 and 65535.\r\n");
                return;
            }
            Config.Write("aprsis.server", split[0]);
            APRSIS.Server = split[0];
            Config.Write("aprsis.port", port.ToString());
            APRSIS.Port = port;
            APRSIS.Connection.Close();
        }
    }

    public class APRSIS
    {
        public static string Server;
        public static int Port = 14580;
        public static int Pass = -1;
        static int KeepAlive = 0;
        public static Socket Connection = null;

        public static void Main()
        {
            Server = Config.Read("aprsis.server");
            try
            {
                Port = int.Parse(Config.Read("aprsis.port"));
            }
            catch { }
            try
            {
                Pass = int.Parse(Config.Read("aprsis.pass"));
            }
            catch { }
            while (true)
            {
                using (Connection)
                {
                    string InData;
                    LEDControl.errors++;
                    try
                    {
                        EndPoint APRSISServer = new IPEndPoint(Dns.GetHostEntry(Server).AddressList[0], Port);
                        Connection = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        Connection.Connect(APRSISServer);
                        Debug.Print("Connected!");
                        Thread.Sleep(1000);
                        SendData("user " + MiniGate.FullCall + " pass " + Pass + " vers MiniGate " + MiniGate.MiniGateVer + "\r\n");
                        Thread keepalive = new Thread(new ThreadStart(Monitor));
                        keepalive.Start();
                        Beacon.SendISBeacon();
                        LEDControl.errors--;
                    }
                    catch
                    {
                        Debug.Print("Exception @ Making connection");
                        Thread.Sleep(10000);
                    }
                    while (IsConnected())
                    {
                        InData = GetInput();
                    }
                    Debug.Print("Socket died!");
                    //PowerState.RebootDevice(true);
                }
            }
        }

        static void Monitor()
        {
            Debug.Print("KeepAlive started!");
            while (KeepAlive++ < 60 && IsConnected())
            {
                Thread.Sleep(1000);
            }
            Debug.Print("KeepAlive quitting! Val=" + KeepAlive.ToString());
            Connection.Close();
        }

        static bool IsConnected()
        {
            if (Connection == null) return false;
            try
            {
                return !(Connection.Poll(100, SelectMode.SelectRead) && (Connection.Available == 0));
            }
            catch (SocketException e)
            {
                Debug.Print("Exception @ IsConnected(): " + e.ErrorCode);
                return false;
            }
        }

        public static void SendData(string TXData)
        {
            if (!IsConnected()) return;
            Debug.Print("OUT: " + TXData.Trim());      // TODO: Remove after testing
            try
            {
                Connection.Send(UTF8Encoding.UTF8.GetBytes(TXData), SocketFlags.None);
            }
            catch { Debug.Print("Exception @ SendData()"); }
        }

        static string GetInput()
        {
            if (!IsConnected())
            {
                Thread.Sleep(1000);
                return "";
            }
            try
            {
                Connection.Poll(-1, SelectMode.SelectRead);
                byte[] RXData = new byte[Connection.Available];
                Connection.Receive(RXData);
                Debug.Print("IN: " + new String(Encoding.UTF8.GetChars(RXData)).Trim());    // TODO: Remove after testing
                KeepAlive = 0;      // Clear KeepAlive watchdog
                return new String(Encoding.UTF8.GetChars(RXData)).Trim();       // TODO: Replace ugly hack with real input validation
                
            }
            catch (SocketException e)
            {
                Debug.Print("Exception @ GetInput(): " + e.ErrorCode);
                return "";
            }
        }
    }

    public class Beacon
    {
        public static string BText;
        public static int Interval;

        public static void Main()
        {
            int Secs = 0;

            BText = Config.Read("stn.btext");
            Interval = int.Parse(Config.Read("stn.binterval"));

            while (true)
            {
                if (Secs++ >= Interval)
                {
                    Secs = 0;
                    SendISBeacon();
                }
                Thread.Sleep(1000);
            }
        }

        public static void SendISBeacon()
        {
            APRSIS.SendData(MiniGate.FullCall + ">" + MiniGate.MiniGateDest + ",TCPIP*:" + BText + "\r\n");
        }
    }
}