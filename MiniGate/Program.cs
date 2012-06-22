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
    public class Program
    {
        static SerialPort modem = new SerialPort("COM2", 9600, Parity.None, 8, StopBits.One);
        static int bytes = 0;
        static byte[] indata = new byte[1024];
        static bool esc = false;
        
        public static void Main()
        {
            Thread ledControl = new Thread(new ThreadStart(LEDControl.BlinkLED));
            ledControl.Start();
            NetworkInterface[] eth = NetworkInterface.GetAllNetworkInterfaces();
            Debug.Print("IP: " + eth[0].IPAddress);
            modem.DataReceived += new SerialDataReceivedEventHandler(modem_DataReceived); // Handler for incoming serial data
            modem.Open();
            Thread telnet = new Thread(new ThreadStart(TelnetServer.StartServer));
            telnet.Start();
            LEDControl.error = false;   // TODO: Only clear the error condition after connecting to APRS-IS, etc.
            Thread.Sleep(Timeout.Infinite);
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
                        parsepacket();
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

        private static void parsepacket()   // Where most of the packet decoding magic happens
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
                        string Dest = new String(UTF8Encoding.UTF8.GetChars(Callsigns[0]));
                        Dest = Dest.Trim();
                        string Payload = new String(UTF8Encoding.UTF8.GetChars(Utility.ExtractRangeFromArray(indata, (NumCalls * 7) + 2, bytes - (NumCalls * 7) - 4)));
                        Debug.Print(Source + ">" + Dest + Via + ":" + Payload);
                    }
                }
            }
            Array.Clear(indata, 0, bytes + 1);
            bytes = 0;
        }
    }

    public class LEDControl
    {
        public static bool error = true;

        public static void BlinkLED()
        {
            OutputPort led = new OutputPort(Pins.ONBOARD_LED, false);
            while (true)
            {
                led.Write(true);
                if (error)
                {
                    Thread.Sleep(250);
                }
                else
                {
                    Thread.Sleep(1500);
                }
                led.Write(false);
                if (error)
                {
                    Thread.Sleep(250);
                }
                else
                {
                    Thread.Sleep(1500);
                }
            }
        }
    }

    public class TelnetServer
    {
        public static void StartServer()
        {
            Socket telnetSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            telnetSock.Bind(new IPEndPoint(IPAddress.Any, 23));
            telnetSock.Listen(1);

            while (true)
            {
                using (Socket telnetConn = telnetSock.Accept())
                {
                    while (!(telnetConn.Available == 0 && telnetConn.Poll(1, SelectMode.SelectRead)))
                    {
                        SendData(telnetConn, "\nMiniGate Console\n\n 1) RF Port Config\n 2) Digipeater Config\n 3) Network Config\n 4) Monitor RF Port\n\nEnter an option: ");
                        string RXData = GetInput(telnetConn);
                        // TODO: Finish telnet interface
                    }
                }
            }
        }

        static string GetInput(Socket telnetConn)
        {
            byte[] RXData = new byte[telnetConn.Available];
            telnetConn.Receive(RXData);
            telnetConn.Poll(-1, SelectMode.SelectRead);
            RXData = new byte[telnetConn.Available];
            telnetConn.Receive(RXData);
            return new String(Encoding.UTF8.GetChars(RXData));
        }

        static void SendData(Socket telnetConn, string TXData)
        {
            byte[] senddata = UTF8Encoding.UTF8.GetBytes(TXData);
            telnetConn.Send(senddata, SocketFlags.None);
        }
    }
}