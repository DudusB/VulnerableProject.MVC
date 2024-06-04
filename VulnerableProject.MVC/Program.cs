using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sast.DIERS.Test.MVC.Controllers;
using Sast.DIERS.Test.MVC.Data;
using Sast.DIERS.Test.MVC.Helper.KeyGenerator;
using Sast.DIERS.Test.MVC.MidlWare;
using Sast.DIERS.Test.MVC.Models;
using Serilog;
using System.Web;

// Example usage in Program.cs or Startup.cs
KeyGenerator.GenerateAndSaveKeyPairPem(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "keys"));
// Assuming this is called in the Configure method or Main method
KeyGenerator.GenerateAndSaveKeyPairXml(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "keys"));

// Initialize Serilog Logger
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("logs/Sast.Diers.Test.MVC.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);

//
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAntiforgery();

builder.Services.AddHttpLogging(logging =>
{
    logging.LoggingFields = HttpLoggingFields.All;
    logging.RequestHeaders.Add("X-Real-IP");
    logging.RequestBodyLogLimit = 4096;
    logging.ResponseBodyLogLimit = 4096;
    logging.CombineLogs = true;
});


// Add Serilog to the builder
builder.Host.UseSerilog();

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddControllersWithViews();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();

//
var configuration = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json").Build();


var app = builder.Build();

//
app.UseAntiforgery();
app.UseMiddleware<XRealIPMiddleware>();
app.UseHttpLogging();
app.UseSwagger();
app.UseSwaggerUI();


// Variables :

var Secret = configuration["Secret"];
var LogFile = configuration["LogFile"];


// Endpoints :

app.MapGet("/lang", async (string? lang) => await Task.FromResult(VVController.VulnerableHelloWorld(HttpUtility.UrlDecode(lang)))).WithOpenApi();

app.MapGet("/Xml", async (string i) => await Task.FromResult(VVController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();

app.MapGet("/Json", async (string i) => await Task.FromResult(VVController.VulnerableDeserialize(HttpUtility.UrlDecode(i)))).WithOpenApi();

app.MapGet("/Req", async (string? i) => await VVController.VulnerableWebRequest(i)).WithOpenApi();

app.MapGet("/Addr", async (string i, string t) => await Task.FromResult(VVController.VulnerableObjectReference(i, t, Secret))).WithOpenApi();

app.MapGet("/Dns", async (string i, string t) => await Task.FromResult(VVController.VulnerableCmd(HttpUtility.UrlDecode(i), t, Secret))).WithOpenApi();

app.MapGet("/NoSQL", async (string s) => await Task.FromResult(VVController.VulnerableNoSQL(HttpUtility.UrlDecode(s)))).WithOpenApi();

app.MapPost("/Auth", [ProducesResponseType(StatusCodes.Status200OK)] async (HttpRequest request, [FromBody] Creds login) => await Task.FromResult(VVController.VulnerableQuery(login.User, login.Passwd, Secret, LogFile)).Result).WithOpenApi();

app.MapPatch("/Patch", async ([FromForm] IFormFile file, [FromHeader(Name = "X-Forwarded-For")] string h, string t) => await VVController.VulnerableHandleFileUpload(file, h, t, Secret, LogFile)).DisableAntiforgery();




// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSession();



app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
//
app.MapControllerRoute(
    name: "helloWorld",
    pattern: "HelloWorld/GetFileContent/{fileName?}",
    defaults: new { controller = "HelloWorld", action = "GetFileContent" });

app.MapControllerRoute(
    name: "xmlParser",
    pattern: "XmlParser/ParseXml",
    defaults: new { controller = "XmlParser", action = "ParseXml" });

app.MapControllerRoute(
    name: "jsonParser",
    pattern: "JsonParser/ParseJson",
    defaults: new { controller = "JsonParser", action = "ParseJson" });

app.MapControllerRoute(
    name: "webRequest",
    pattern: "WebRequest/MakeRequest",
    defaults: new { controller = "WebRequest", action = "MakeRequest" });

app.MapControllerRoute(
    name: "userInfo",
    pattern: "UserInfo/GetUserInfo",
    defaults: new { controller = "UserInfo", action = "GetUserInfo" });

app.MapControllerRoute(
    name: "dnsRequest",
    pattern: "DnsRequest/PerformDnsRequest",
    defaults: new { controller = "DnsRequest", action = "PerformDnsRequest" });

app.MapControllerRoute(
    name: "nosql",
    pattern: "NoSQL/PerformQuery",
    defaults: new { controller = "NoSQL", action = "PerformQuery" });


app.MapRazorPages();

app.Run();
