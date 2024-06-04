using System.Security.Cryptography;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Sast.DIERS.Test.MVC.Helper.KeyGenerator;


public class KeyGenerator
{
    public static void GenerateAndSaveKeyPairPem(string folderPath)
    {
        // Ensure the target directory exists, create it if it does not
        if (!Directory.Exists(folderPath))
        {
            Directory.CreateDirectory(folderPath);
        }

        using (var rsa = new RSACryptoServiceProvider(2048)) // Generate a new 2048-bit RSA key
        {
            // Export the public key
            var publicKey = ExportPublicKey(rsa);
            // Export the private key
            var privateKey = ExportPrivateKey(rsa);

            // Write the public key to a file
            File.WriteAllText(Path.Combine(folderPath, "publicKey.pem"), publicKey);
            // Write the private key to a file
            File.WriteAllText(Path.Combine(folderPath, "privateKey.pem"), privateKey);
        }
    }

    public static void GenerateAndSaveKeyPairXml(string folderPath)
    {
        using (var rsa = new RSACryptoServiceProvider(2048)) // Generate a new 2048-bit RSA key
        {
            string publicKey = rsa.ToXmlString(false); // Export the public key
            string privateKey = rsa.ToXmlString(true); // Export the private key

            // Ensure the directory exists
            if (!Directory.Exists(folderPath))
            {
                Directory.CreateDirectory(folderPath);
            }

            // Write the keys to files
            File.WriteAllText(Path.Combine(folderPath, "publicKey.xml"), publicKey);
            File.WriteAllText(Path.Combine(folderPath, "privateKey.xml"), privateKey);
        }
    }

    private static string ExportPublicKey(RSACryptoServiceProvider csp)
    {
        var parameters = csp.ExportParameters(false);
        using (var sw = new StringWriter())
        {
            var pkey = new PemWriter(sw);
            pkey.WritePublicKey(parameters);
            return sw.ToString();
        }
    }

    private static string ExportPrivateKey(RSACryptoServiceProvider csp)
    {
        var parameters = csp.ExportParameters(true);
        using (var sw = new StringWriter())
        {
            var pkey = new PemWriter(sw);
            pkey.WritePrivateKey(parameters);
            return sw.ToString();
        }
    }

    class PemWriter
    {
        private StringWriter writer;

        public PemWriter(StringWriter sw)
        {
            this.writer = sw;
        }

        public void WritePublicKey(RSAParameters param)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN PUBLIC KEY-----");
            builder.AppendLine(Convert.ToBase64String(param.Modulus));
            builder.AppendLine("-----END PUBLICITY KEY-----");
            writer.Write(builder.ToString());
        }

        public void WritePrivateKey(RSAParameters param)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(param.Modulus));
            builder.AppendLine("-----END PRIVATE KEY-----");
            writer.Write(builder.ToString());
        }
    }
}