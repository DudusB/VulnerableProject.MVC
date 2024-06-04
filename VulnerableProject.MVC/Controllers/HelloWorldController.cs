using Microsoft.AspNetCore.Mvc;

namespace VulnerableProject.MVC.Controllers;

public class HelloWorldController : Controller
{
    // Action method to call the VulnerableHelloWorld method
    [HttpGet("/HelloWorld/GetFileContent")]
    public IActionResult GetFileContent(string fileName = "english")
    {
        var result = VulnerableHelloWorld(fileName);

        if (result == null)
        {
            return NotFound("File not found or invalid file name.");
        }

        return result as IActionResult;
    }

    // Existing VulnerableHelloWorld method
    public static IActionResult VulnerableHelloWorld(string FileName = "english")
    {
        try
        {
            /*
            Retourne le contenu du fichier correspondant à la langue choisie par l'utilisateur
            */
            if (string.IsNullOrEmpty(FileName)) FileName = "francais";
            string content = System.IO.File.ReadAllText(FileName.Replace("../", "").Replace("..\\", ""));

            return new OkObjectResult(content);
        }
        catch (FileNotFoundException)
        {
            return new NotFoundResult();
        }
        catch (IOException)
        {
            return new StatusCodeResult(500); // Internal Server Error
        }
    }
}