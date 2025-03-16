using System;
using System.IO;

class rapp
{
    static void Main()
    {
        Console.WriteLine("Welcome, brave soul, to the binary inspector...");
        string configFile = "config.json";
        string binaryFile = "bin.txt";

        if (!File.Exists(configFile))
        {
            Console.WriteLine("Bruh, No config file found.");
        }
        else
        {
            Console.WriteLine($"Found config! here's it:\n{File.ReadAllText(configFile)}");
        }

        if (!File.Exists(binaryFile))
        {
            Console.WriteLine("Binary file not found! What even is this?");
        }
        else
        {
            Console.WriteLine("\nBehold the raw binary file content:");
            byte[] data = File.ReadAllBytes(binaryFile);
            Console.WriteLine(BitConverter.ToString(data).Replace("-", " "));
        }

        Console.WriteLine("\nThat's it. Go have a coffee or something sht.");
    }
}
