using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace VulnerableProject.MVC.Controllers;
public class WebRequestController : Controller
{
    // Action method to display the form and the result
    [HttpGet("/WebRequest/MakeRequest")]
    public IActionResult MakeRequest()
    {
        return View();
    }

    // Action method to handle the form submission
    [HttpPost("/WebRequest/MakeRequest")]
    public async Task<IActionResult> MakeRequest(string uri)
    {
        if (string.IsNullOrEmpty(uri))
        {
            ViewBag.Error = "URI input is required.";
            return View();
        }

        try
        {
            var result = await VulnerableWebRequest(uri);
            ViewBag.Result = result;
        }
        catch (Exception ex)
        {
            // Log the exception as needed
            ViewBag.Error = $"Internal server error: {ex.Message}";
        }

        return View();
    }

    // Existing VulnerableWebRequest method
    public static async Task<object> VulnerableWebRequest(string Uri = "https://localhost:3000/")
    {
        /*
        Effectue une requête web sur la boucle locale
        */
        if (string.IsNullOrEmpty(Uri)) Uri = "https://localhost:3000/";
        if (Regex.IsMatch(Uri, @"^https://localhost"))
        {
            using HttpClient Client = new();
            Client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));

            var Resp = await exec(Client, Uri);
            static async Task<string> exec(HttpClient client, string uri)
            {
                var Result = await client.GetAsync(uri);
                Result.EnsureSuccessStatusCode();
                return Result.StatusCode.ToString();
            }
            return new OkObjectResult(Resp);
        }
        else return new UnauthorizedResult();
    }
}
