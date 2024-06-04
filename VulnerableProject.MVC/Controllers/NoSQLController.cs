using Microsoft.AspNetCore.Mvc;
using Sast.DIERS.Test.MVC.Models;
using System.Linq.Dynamic.Core;

namespace VulnerableProject.MVC.Controllers;

public class NoSQLController : Controller
{
    // Action method to display the form
    [HttpGet("/NoSQL/PerformQuery")]
    public IActionResult PerformQuery()
    {
        return View();
    }

    // Action method to handle the form submission
    [HttpPost("/NoSQL/PerformQuery")]
    public IActionResult PerformQuery(string userStr)
    {
        if (string.IsNullOrEmpty(userStr))
        {
            ViewBag.Error = "Input is required.";
            return View();
        }

        try
        {
            var result = VulnerableNoSQL(userStr);
            ViewBag.Result = result;
        }
        catch (Exception ex)
        {
            // Log the exception as needed
            ViewBag.Error = $"Internal server error: {ex.Message}";
        }

        return View();
    }

    // Existing VulnerableNoSQL method
    public static object VulnerableNoSQL(string UserStr)
    {
        /*
        Retourne le résultat de la requête NoSQL fournie en paramètre
        */
        if (UserStr.Length > 250) return Results.Unauthorized();
        List<Employee> Employees = VVData.GetEmployees();
        var Query = Employees.AsQueryable();

        return Results.Ok(Query.Where(UserStr).ToArray().ToString());
    }

    // Stub class for Results to make the code compile
    public static class Results
    {
        public static IActionResult Ok(object value) => new OkObjectResult(value);
        public static IActionResult Unauthorized() => new UnauthorizedResult();
    }

    // Existing VVData class
    public static class VVData
    {
        public static List<Employee> GetEmployees() => new List<Employee>
        {
            new Employee { Id = "1", Name = "Steven", Age = 21, Address = "123 Main St" },
            new Employee { Id = "2", Name = "George", Age = 30, Address = "456 Maple Ave" }
        };
    }

}
