using Microsoft.AspNetCore.Mvc;

namespace Sast.DIERS.Test.MVC.Models;

    public class LoginViewModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }