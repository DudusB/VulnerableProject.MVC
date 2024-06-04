using Microsoft.AspNetCore.Mvc;
using Sast.DIERS.Test.MVC.Models;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace Sast.DIERS.Test.MVC.Controllers;

public class AccountSessionController : Controller
{
    private readonly string adminLogin = "admin";
    private readonly string hashedAdminPassword; // Store hashed password
    private static readonly byte[] aesKey = Encoding.UTF8.GetBytes("1234567812345678"); // 16 bytes for AES-128

    public AccountSessionController()
    {
        // Hashing the password '1' using SHA1
        hashedAdminPassword = ComputeSha1Hash("1");
    }

    [HttpGet]
    public ActionResult Login()
    {
        ViewBag.adminUser = adminLogin;
        ViewBag.EncryptedAdminPassword = Convert.ToBase64String(EncryptData("1"));
        return View();
    }

    [HttpPost]
    public ActionResult Login(LoginViewModel model)
    {
        string hashedInputPassword = ComputeSha1Hash(model.Password);

        if (model.Username == adminLogin && hashedInputPassword == hashedAdminPassword)
        {
            HttpContext.Session.SetString("User", model.Username);
            return RedirectToAction("SecureArea", "Admin");
        }

        ModelState.AddModelError("", "Invalid login attempt.");
        return View(model);
    }

    private byte[] EncryptData(string plainText)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = aesKey;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.IV = new byte[16]; // Zero initialization vector for simplicity

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }
                return msEncrypt.ToArray();
            }
        }
    }

    private string ComputeSha1Hash(string input)
    {
        using (SHA1 sha1 = SHA1.Create())
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = sha1.ComputeHash(inputBytes);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2"));
            }
            return sb.ToString();
        }
    }
}