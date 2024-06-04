using Microsoft.AspNetCore.Mvc;
using Sast.DIERS.Test.MVC.Models;
using System.Diagnostics;

namespace Sast.DIERS.Test.MVC.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;
        private static readonly HttpClient httpClient;


        static HomeController()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
            httpClient = new HttpClient(handler);
        }

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;

        }

        public IActionResult Index()
        {
            // Reading database credentials
            var username = _configuration["DatabaseCredentials:Username"];
            var password = _configuration["DatabaseCredentials:Password"];

            ViewBag.Message = $"Database Username: {username}, Password: {password}";

            return View();
        }

        public IActionResult WeakRandomNumber()
        {
            // Utilize System.Random for a cryptographic operation
            Random random = new Random();
            byte[] buffer = new byte[16]; // For example, creating a 128-bit token
            random.NextBytes(buffer); // Filling the buffer with "random" data

            // Convert to a base64 string to simulate a token
            string token = Convert.ToBase64String(buffer);

            ViewBag.Token = token;
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }


        private static readonly HttpClient httpClientSendingData = new HttpClient();

        public async Task<IActionResult> SendSensitiveDataNonSsl()
        {
            string url = "http://google.com.neverssl.com/online/"; // Non-SSL HTTP URL
            var content = new StringContent("username=admin&password=admin123", System.Text.Encoding.UTF8, "application/x-www-form-urlencoded");

            var response = await httpClientSendingData.PostAsync(url, content);

            ViewBag.ResponseNonSsl = await response.Content.ReadAsStringAsync();
            return View();
        }
        public async Task<IActionResult> SendSensitiveDataSslValidOff()
        {
            string url = "https://revoked.badssl.com/"; // Now using an HTTPS URL
            var content = new StringContent("username=admin&password=admin123", System.Text.Encoding.UTF8, "application/x-www-form-urlencoded");

            var response = await httpClient.PostAsync(url, content);

            ViewBag.ResponseSslValidOff = await response.Content.ReadAsStringAsync();
            return View();
        }
        public IActionResult LogPatientData()
        {
            // Simulate receiving patient data
            var patient = new Patient
            {
                Name = "John Doe",
                Age = 30,
                Gender = "Non-Binary",
                MedicalCondition = "Type 1 Diabetes"
            };

            // Log the patient's data without sanitization
            _logger.LogInformation($"Logging Patient Data: Name - {patient.Name}, Age - {patient.Age}, Gender - {patient.Gender}, Medical Condition - {patient.MedicalCondition}");
            ViewBag.Patient = patient;

            return View();
        }
        public IActionResult SendPatientData(string name, int age, string gender, string condition)
        {
            // Logically here, you would process the data
            ViewBag.PatientName = GenerateRandomName();
            ViewBag.PatientAge = GenerateRandomAge();
            ViewBag.PatientGender = GenerateRandomGender();
                        ViewBag.MedicalCondition = GenerateRandomCondition();

            _logger.LogInformation($"Logging Patient Data: Name - {name}, Age - {age}, Gender - {gender}, Medical Condition - {condition}");

            return View();

            string GenerateRandomName()
            {
                string[] names = { "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Skyler", "Reese", "Robin" };
                Random rand = new Random();
                int index = rand.Next(names.Length);
                return names[index];
            }

            int GenerateRandomAge()
            {
                Random rand = new Random();
                return rand.Next(20, 80);  // Generates a random age between 20 and 80
            }
             string GenerateRandomGender()
            {
                string[] genders = { "Male", "Female", "Non-Binary", "Genderqueer", "Genderfluid" };
                Random rand = new Random();
                int index = rand.Next(genders.Length);
                return genders[index];
            }

             string GenerateRandomCondition()
            {
                string[] conditions = { "Type 1 Diabetes", "Type 2 Diabetes", "Hypertension", "Asthma", "Depression", "Anxiety" };
                Random rand = new Random();
                int index = rand.Next(conditions.Length);
                return conditions[index];
            }
        }

        

       
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
