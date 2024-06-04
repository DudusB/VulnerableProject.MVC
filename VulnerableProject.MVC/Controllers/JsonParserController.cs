using Newtonsoft.Json;
using Microsoft.IdentityModel.Tokens;
using Sast.DIERS.Test.MVC.Models;
using Microsoft.AspNetCore.Mvc;


namespace VulnerableProject.MVC.Controllers;

public class JsonParserController : Controller
{
    // Action method to display the form and the result
    [HttpGet("/JsonParser/ParseJson")]
    public IActionResult ParseJson()
    {
        return View();
    }

    // Action method to handle the form submission
    [HttpPost("/JsonParser/ParseJson")]
    public IActionResult ParseJson(string json)
    {
        if (string.IsNullOrEmpty(json))
        {
            ViewBag.Error = "JSON input is required.";
            return View();
        }

        try
        {
            var result = VulnerableDeserialize(json);
            ViewBag.Result = result.ToString();
        }
        catch (Exception ex)
        {
            // Log the exception as needed
            ViewBag.Error = $"Internal server error: {ex.Message}";
        }

        return View();
    }

    // Existing VulnerableDeserialize method
    public static object VulnerableDeserialize(string Json)
    {
        /*
        Deserialise les données JSON passées en paramètre.
        On enregistre les objets "employé" valides dans un fichier en lecture seule
        */
        string NewId = "-1";
        string HaveToBeEmpty = string.Empty;
        string ROFile = "NewEmployees.txt";
        Json = Json.Replace("Framework", "").Replace("Token", "").Replace("Cmd", "").Replace("powershell", "").Replace("http", "");

        if (!System.IO.File.Exists(ROFile)) System.IO.File.Create(ROFile).Dispose();
        System.IO.File.SetAttributes(ROFile, FileAttributes.ReadOnly);

        JsonConvert.DeserializeObject<object>(Json, new JsonSerializerSettings() { TypeNameHandling = TypeNameHandling.All });
        Employee NewEmployee = JsonConvert.DeserializeObject<Employee>(Json);

        if (NewEmployee != null && !NewEmployee.Address.IsNullOrEmpty() && !NewEmployee.Id.IsNullOrEmpty())
        {
            HaveToBeEmpty = VulnerableBuffer(NewEmployee.Address);
            if (HaveToBeEmpty.IsNullOrEmpty())
            {
                NewId = VulnerableCodeExecution(NewEmployee.Id);
                System.IO.File.SetAttributes(ROFile, FileAttributes.Normal);
                using (StreamWriter sw = new StreamWriter(ROFile, true)) sw.Write(JsonConvert.SerializeObject(NewEmployee, Newtonsoft.Json.Formatting.Indented));
                System.IO.File.SetAttributes(ROFile, FileAttributes.ReadOnly);
            }
        }

        return Results.Ok($"File is : {System.IO.File.GetAttributes(ROFile).ToString()}    New id : {NewId}    Empty Var: {HaveToBeEmpty.IsNullOrEmpty()}");
    }

    // Stub methods for VulnerableBuffer and VulnerableCodeExecution to make the code compile
    private static string VulnerableBuffer(string input) => string.Empty;
    private static string VulnerableCodeExecution(string input) => "new-id";
}


