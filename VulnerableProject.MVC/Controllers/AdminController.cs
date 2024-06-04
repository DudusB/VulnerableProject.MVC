using Microsoft.AspNetCore.Mvc;

namespace Sast.DIERS.Test.MVC.Controllers;

public class AdminController : Controller
{
    // Method to display secure area
    [HttpGet]
    public IActionResult SecureArea()
    {
        // Check if the user session is set
        if (HttpContext.Session.GetString("User") == null)
        {
            // Redirect to Login if no user is in session
            return RedirectToAction("Login", "Account");
        }

        // Proceed to the secure area view
        return View();
    }
}