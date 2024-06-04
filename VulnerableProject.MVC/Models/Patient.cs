namespace Sast.DIERS.Test.MVC.Models;

public class Patient
{
    public string Name { get; set; }
    public int Age { get; set; }
    public string Gender { get; set; } // Includes Male, Female, Non-Binary
    public string MedicalCondition { get; set; }
}
