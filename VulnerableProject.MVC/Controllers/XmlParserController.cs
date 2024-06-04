using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Xml.Linq;
using System.Xml.Xsl;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableProject.MVC.Controllers;
public class XmlParserController : Controller
{
    // Action method to display the form and the result
    [HttpGet("/XmlParser/ParseXml")]
    public IActionResult ParseXml()
    {
        return View();
    }

    // Action method to handle the form submission
    [HttpPost("/XmlParser/ParseXml")]
    public IActionResult ParseXml(string xml)
    {
        if (string.IsNullOrEmpty(xml))
        {
            ViewBag.Error = "XML input is required.";
            return View();
        }

        try
        {
            var result = VulnerableXmlParser(xml);
            ViewBag.Result = result;
        }
        catch (Exception ex)
        {
            // Log the exception as needed
            ViewBag.Error = $"Internal server error: {ex.Message}";
        }

        return View();
    }

    // Existing VulnerableXmlParser method
    public static string VulnerableXmlParser(string Xml)
    {
        /*
        Parse les données XML passées en paramètre et retourne son contenu
        */
        try
        {
            var Xsl = XDocument.Parse(Xml);
            var MyXslTrans = new XslCompiledTransform(enableDebug: true);
            var Settings = new XsltSettings();
            MyXslTrans.Load(Xsl.CreateReader(), Settings, null);
            var DocReader = XDocument.Parse("<doc></doc>").CreateReader();

            var Sb = new StringBuilder();
            var DocWriter = XmlWriter.Create(Sb, new XmlWriterSettings() { ConformanceLevel = ConformanceLevel.Fragment });
            MyXslTrans.Transform(DocReader, DocWriter);

            return Sb.ToString();
        }
        catch (Exception ex)
        {
            Xml = Xml.Replace("Framework", "").Replace("Token", "").Replace("Cmd", "").Replace("powershell", "").Replace("http", "");
            XmlReaderSettings ReaderSettings = new XmlReaderSettings();
            ReaderSettings.DtdProcessing = DtdProcessing.Parse;
            ReaderSettings.XmlResolver = new XmlUrlResolver();
            ReaderSettings.MaxCharactersFromEntities = 6000;

            using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(Xml)))
            {
                XmlReader Reader = XmlReader.Create(stream, ReaderSettings);
                var XmlDocument = new XmlDocument();
                XmlDocument.XmlResolver = new XmlUrlResolver();
                XmlDocument.Load(Reader);

                return XmlDocument.InnerText;
            }
        }
    }
}


