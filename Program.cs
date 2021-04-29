using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GenerateCABundle
{
    class Program
    {
        public static string GetCABundleFromStore()
        {
            var strb = new StringBuilder();
            var now = DateTime.UtcNow;
            using (var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                foreach (var cert in store.Certificates)
                {
                    // only generate ameroot
                    if (cert.Subject.IndexOf("ameroot", StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        continue;
                    }

                    if (cert.NotAfter > now && cert.NotBefore < now)
                    {
                        Console.WriteLine($"Add {cert.Subject}");
                        strb.AppendLine("-----BEGIN CERTIFICATE-----");
                        var pem = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
                        while (true)
                        {
                            var len = Math.Min(pem.Length, 64);
                            strb.AppendLine($"{pem.Substring(0, len)}");
                            if (pem.Length <= 64)
                                break;
                            pem = pem.Substring(len);
                        }
                        strb.AppendLine("-----END CERTIFICATE-----");
                    }
                    else
                    {
                        Console.WriteLine($"Expired {cert.Subject}");
                    }

                    store.Close();
                }
            }

            return strb.ToString();
        }

        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    Console.WriteLine(@"GenerateCABundle.exe c:\temp\ameroot-ca-bundle.crt");
                    return;
                }

                var bundle = GetCABundleFromStore();
                var file = args[0];
                if (!File.Exists(file))
                {
                    File.WriteAllText(file, bundle);
                    Console.WriteLine($"{file} saved successfully");
                }
                else
                {
                    var exist = File.ReadAllText(file);
                    if (!string.Equals(bundle, exist))
                    {
                        File.WriteAllText(file, bundle);
                        Console.WriteLine($"{file} saved successfully");
                    }
                    else
                    {
                        Console.WriteLine($"{file} unchanged");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}