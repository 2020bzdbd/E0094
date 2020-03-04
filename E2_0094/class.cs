using System;
using System.IO.Ports;
using System.Threading;

public class PortChat
{
    static bool _continue;
    static SerialPort _serialPort;
    public static void Main(string[] args)
    {
        string message;
        StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;
        Thread readThread = new Thread(Read);
        _serialPort = new SerialPort("com1",9600,Parity.None,8,StopBits.One);

        _serialPort.ReadTimeout = 500;
        _serialPort.WriteTimeout = 500;

        if(!_serialPort.IsOpen)
        _serialPort.Open();

        _continue = true;
        readThread.Start();

        Console.WriteLine("Type QUIT to exit");

        while (_continue)
        {
            message = Console.ReadLine();

            if (stringComparer.Equals("quit", message))
            {
                _continue = false;
            }
            else
            {
                if (message != "")
                    Console.WriteLine("[SENT {0}] {1}", DateTime.Now.ToLocalTime().ToString(), message);
                _serialPort.WriteLine(
                    String.Format("[SENT {0}] {1}", DateTime.Now.ToLocalTime().ToString(), message));
            }
        }

        readThread.Join();
        _serialPort.Close();
    }

    public static void Read()
    {
        while (_continue)
        {
            try
            {
                string message = _serialPort.ReadLine();
                Console.WriteLine("[RECV {0}]{1}",DateTime.Now.ToLocalTime().ToString(),message);
            }
            catch (TimeoutException) { }
        }
    }

}
