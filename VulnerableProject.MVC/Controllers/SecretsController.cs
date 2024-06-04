using Microsoft.AspNetCore.Mvc;

namespace Sast.DIERS.Test.MVC.Controllers;

public class SecretsController : Controller
{
	private string secretApiKey = "12345-abcde-secretkey-exposed";

	public IActionResult Index()
	{
		// Directly using the secret key in the logic, which will also be exposed to the view
		ViewBag.ApiKey = secretApiKey;
		return View();
	}
    public IActionResult ExposeSecretDirectly()
	{
		return Content($"The secret API key is: {secretApiKey}");
	}
}