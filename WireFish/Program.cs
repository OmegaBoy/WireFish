using PacketDotNet;
using SharpPcap;
using System.Configuration;

namespace WireFish
{
    class Program
    {
        // used to stop the capture loop
        private static bool _stopCapturing;

        public static void Main(string[] args)
        {
            var logger = new SQLiteLogger("WireFish.db");

            // Print SharpPcap version
            var ver = SharpPcap.Pcap.SharpPcapVersion;
            Console.WriteLine("PacketDotNet example using SharpPcap {0}", ver);

            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            var i = 0;
            if (ConfigurationManager.AppSettings["CaptureDevice"] == null)
            {
                Console.WriteLine();
                Console.WriteLine("The following devices are available on this machine:");
                Console.WriteLine("----------------------------------------------------");
                Console.WriteLine();


                // Print out the devices
                foreach (var dev in devices)
                {
                    /* Description */
                    Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                    i++;
                }

                Console.WriteLine();
                Console.Write("-- Please choose a device to capture: ");

                i = int.Parse(Console.ReadLine() ?? throw new InvalidOperationException());
            }
            else
            {
                i = int.Parse(ConfigurationManager.AppSettings["CaptureDevice"]);
            }

            var defaultOutputType = StringOutputType.Normal;
            StringOutputType selectedOutputType = defaultOutputType;
            if (ConfigurationManager.AppSettings["Verbosity"] == null)
            {
                Console.WriteLine();
                Console.WriteLine("Output Verbosity Options");
                Console.WriteLine("----------------------------------------------------");
                Console.WriteLine();
                var outputTypeValues = Enum.GetValues(typeof(StringOutputType));
                foreach (StringOutputType outputType in outputTypeValues)
                {
                    Console.Write("{0} - {1}", (int)outputType, outputType);
                    if (outputType == defaultOutputType)
                    {
                        Console.Write(" (default)");
                    }

                    Console.WriteLine("");
                }

                Console.WriteLine();
                Console.Write("-- Please choose a verbosity (or press enter for the default): ");
                int userSelectedOutputType;
                if (int.TryParse(Console.ReadLine(), out userSelectedOutputType))
                {
                    selectedOutputType = (StringOutputType)userSelectedOutputType;
                }
            }
            else
            {
                selectedOutputType = (StringOutputType)int.Parse(ConfigurationManager.AppSettings["Verbosity"]);
            }

            // Register a cancel handler that lets us break out of our capture loop
            Console.CancelKeyPress += HandleCancelKeyPress;

            var device = devices[i];

            // Open the device for capturing
            var readTimeoutMilliseconds = 1000;
            device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0}, hit 'ctrl-c' to stop...",
                              device.Name);

            while (_stopCapturing == false)
            {
                PacketCapture e;
                var status = device.GetNextPacket(out e);

                // null packets can be returned in the case where
                // the GetNextRawPacket() timed out, we should just attempt
                // to retrieve another packet by looping the while() again
                if (status != GetPacketStatus.PacketRead)
                {
                    // go back to the start of the while()
                    continue;
                }

                var rawCapture = e.GetPacket();

                // use PacketDotNet to parse this packet and print out
                // its high level information
                var p = Packet.ParsePacket(rawCapture.GetLinkLayers(), rawCapture.Data);

                if (p is EthernetPacket)
                {
                    var tcpPacket = p.Extract<TcpPacket>();
                    if (tcpPacket != null && tcpPacket.PayloadData.Length > 0)
                    {
                        var dataString = System.Text.Encoding.UTF8.GetString(tcpPacket.PayloadData);
                        if (dataString.Contains("HTTP"))
                        {
                            if (bool.Parse(ConfigurationManager.AppSettings["LogSource"]))
                            {
                                switch (tcpPacket.SourcePort)
                                {
                                    case 443:
                                        logger.Log("Encrypted\n" + dataString);
                                        break;
                                    case 80:
                                        logger.Log(dataString);
                                        break;
                                    default:
                                        break;
                                } 
                            }
                            if (bool.Parse(ConfigurationManager.AppSettings["LogDestination"]))
                            {
                                switch (tcpPacket.DestinationPort)
                                {
                                    case 443:
                                        logger.Log("Encrypted\n" + dataString);
                                        break;
                                    case 80:
                                        logger.Log(dataString);
                                        break;
                                    default:
                                        break;
                                }  
                            }
                        }
                    }
                }
            }

            Console.WriteLine("-- Capture stopped");

            // Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());

            // Close the pcap device
            device.Close();
        }

        static void HandleCancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("-- Stopping capture");
            _stopCapturing = true;

            // tell the handler that we are taking care of shutting down, don't
            // shut us down after we return because we need to do just a little
            // bit more processing to close the open capture device etc
            e.Cancel = true;
        }
    }
}
