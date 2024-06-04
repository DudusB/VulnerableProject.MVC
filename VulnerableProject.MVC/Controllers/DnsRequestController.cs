using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace VulnerableProject.MVC.Controllers;

public class DnsRequestController : Controller
{
    // Action method to display the form
    [HttpGet("/DnsRequest/PerformDnsRequest")]
    public IActionResult PerformDnsRequest()
    {
        return View();
    }

    // Action method to handle the form submission
    [HttpPost("/DnsRequest/PerformDnsRequest")]
    public IActionResult PerformDnsRequest(string userStr, string token, string secret)
    {
        if (string.IsNullOrEmpty(userStr) || string.IsNullOrEmpty(token) || string.IsNullOrEmpty(secret))
        {
            ViewBag.Error = "All inputs are required.";
            return View();
        }

        try
        {
            var result = VulnerableCmd(userStr, token, secret);
            ViewBag.Result = result;
        }
        catch (Exception ex)
        {
            // Log the exception as needed
            ViewBag.Error = $"Internal server error: {ex.Message}";
        }

        return View();
    }

    // Existing VulnerableCmd method
    public static object VulnerableCmd(string UserStr, string Token, string Secret)
    {
        /*
        Effectue une requête DNS pour le FQDN passé en paramètre
        */
        if (VulnerableValidateToken(Token, Secret) && Regex.Match(UserStr, @"^(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z]{2,}(?:.{0,20})$").Success)
        {
            Process Cmd = new Process();
            Cmd.StartInfo.FileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "cmd" : "/bin/sh";
            Cmd.StartInfo.RedirectStandardInput = true;
            Cmd.StartInfo.RedirectStandardOutput = true;
            Cmd.StartInfo.CreateNoWindow = true;
            Cmd.StartInfo.UseShellExecute = false;
            Cmd.Start();
            Cmd.WaitForExit(200);
            Cmd.StandardInput.WriteLine("nslookup " + UserStr);
            Cmd.StandardInput.Flush();
            Cmd.StandardInput.Close();

            return Results.Ok(Cmd.StandardOutput.ReadToEnd());
        }
        else return Results.Unauthorized();
    }

    // Existing VulnerableValidateToken method
    public static bool VulnerableValidateToken(string Token, string Secret)
    {
        /*
        Vérifie la validité du token JWT passé en paramètre
        */
        var TokenHandler = new JwtSecurityTokenHandler();
        var Key = Encoding.ASCII.GetBytes(Secret);
        bool Result = true;
        try
        {
            var JwtSecurityToken = TokenHandler.ReadJwtToken(Token);
            if (JwtSecurityToken.Header.Alg == "HS256" && JwtSecurityToken.Header.Typ == "JWT")
            {
                TokenHandler.ValidateToken(Token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                }, out SecurityToken validatedToken);

                var JwtToken = (JwtSecurityToken)validatedToken;
            }
        }
        catch { Result = false; }

        return Result;
    }

    // Stub class for Results to make the code compile
    public static class Results
    {
        public static IActionResult Ok(object value) => new OkObjectResult(value);
        public static IActionResult Unauthorized() => new UnauthorizedResult();
    }
}
