using System;

namespace Client
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string input = "This is a test string.";

            if (args.Length > 0)
            {
                input = args[0];
            }

            int length = CliPInvoke.Native.CGetStringLength(input);
            Console.WriteLine("String '{0}' has a length {1}.", input, length);
            CliInterop.MTestClass m = new CliInterop.MTestClass();
            length = m.GetStringLength(input);
            Console.WriteLine("String '{0}' has a length {1}.", input, length);
            length = m.GetStringLength2(input);
            Console.WriteLine("String '{0}' has a length {1}.", input, length);
            length = m.GetStringLength3(input);
            Console.WriteLine("String '{0}' has a length {1}.", input, length);
            length = m.GetStringLength4(input);
            Console.WriteLine("String '{0}' has a length {1}.", input, length);
        }
    }
}
