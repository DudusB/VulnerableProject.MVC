using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Sast.DIERS.Test.MVC.Models;

namespace VulnerableProject.MVC.Controllers;

public class UserInfoController : Controller
{
    // Action method to display the form
    [HttpGet("/UserInfo/GetUserInfo")]
    public IActionResult GetUserInfo()
    {
        return View();
    }

    // Action method to handle the form submission
    [HttpPost("/UserInfo/GetUserInfo")]
    public IActionResult GetUserInfo(string id, string token, string secret)
    {
        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(token) || string.IsNullOrEmpty(secret))
        {
            ViewBag.Error = "All inputs are required.";
            return View();
        }

        try
        {
            var result = VulnerableObjectReference(id, token, secret);
            ViewBag.Result = result;
        }
        catch (Exception ex)
        {
            // Log the exception as needed
            ViewBag.Error = $"Internal server error: {ex.Message}";
        }

        return View();
    }

    // Existing VulnerableObjectReference method
    public static object VulnerableObjectReference(string Id, string Token, string Secret)
    {
        /*
        Retourne les informations liées à l'ID de l'utilisateur
        */
        List<Employee> Employees = VVData.GetEmployees();
        var Address = Employees.Where(x => Id == x.Id)?.FirstOrDefault()?.Address;
        if ((!VulnerableValidateToken(Token, Secret)) || string.IsNullOrEmpty(Address)) return Results.Unauthorized();

        return Results.Ok(Address);
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
    public static class VVData
    {
        public static List<Employee> GetEmployees() => new List<Employee>
    {
        new Employee { Id = "1", Name = "Steven", Age = 21, Address = "123 Main St" },
        new Employee { Id = "2", Name = "George", Age = 30, Address = "456 Maple Ave" }
    };
    }
}

// Stub class for Results to make the code compile
public static class Results
{
    public static IActionResult Ok(object value) => new OkObjectResult(value);
    public static IActionResult Unauthorized() => new UnauthorizedResult();
}
