using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace Sast.DIERS.Test.MVC.Controllers
{
    public class SecurityController : Controller
    {
        // Embedded private key (placeholder - replace with actual private key)
        private readonly string privateKey = @"-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC5Mfs37MLJCA1d
E8HVKzOSOMoUBTDEbl5q/P1loQBKS4hh8mAcwWgE1QG+lfzRtMh2noME8mstzcVR
CuXvgho15RUn0h9p34+SAP1UVnE7YWQs/6aDAuoz8Zr5Mw31Nbq8d7hMewta5quE
5HgDMY9QvuSRpGkJHRTJFGsW+n3+TbtA63HdeQptddw/Kkme4U2YhaFoi+6iqdTb
6pBYbFht29JnnrG+t5utQVcgRlgJufJ61ragwqjO3o9AMzceabgpPUXPMyCniRVQ
w5ncZaHfAQ0eDVP43qyplBcvIbkwIr+HhAZm1r9FvKBAw/gP96j4xe0ya+XM6gBD
i627pLzJAgMBAAECggEBAITKYefnzIN5Upu63vGK2J+wOLXCQwWWXf05CjklCKA9
KL2SnXgA9iUA1w9hXLbBejwTzL5vVIqzURibR+RE1aZvbIvxDrVLqBZ4vy0KDocV
fk8FwM+P937nbsfg49E/hXY+Idg1Ih875yCS8brYfnrXZe1IhkgSoiTMjz0av9zn
h0Z7rJneD9ur/3QYhjuP1cESgjfNJt+68zh0EX/Plt4ZpQPnkZh+SHfThqbBISjW
CK0XLMrVkIXSaqX4QHkUPLOmSFZshs40JiycuMqUPU+PGQFsEDN48Vv2lrdr+NOL
5HmvkCDFTdonrDkHDnWMXQz2jl4ObJpBROA3xfeX+kECgYEA4IO0Ueak0HIupvRQ
3XXdp34g5Rc1Cc+9eYDEFXOnrT9eZkcOv2kliepxDtgXKPEFl97LXXlmPWKvmqSM
hB2sUL+y/wVNIAgjZeaaElzkkLVIc6xrrw4WYphgzPCqDeD09LqeqmkVm4+HJ/3P
urvadnryfP/JiKUfsOdO2pslTRsCgYEA0yqtTVin5PGgJEuAzs6t9a2+D4DCjF6j
CTqviNGWFjs2io+KVpJ/rC6R4aJbPufw1l12KD5yUrF2bV8OeedDKznutgcPmDqp
0syN6ZrNd3j4932h5Zhc4JKCEkuzovG2rspYn6DlO5j6mXeVRwWx4myikJj7Yx9Y
09dUwtStL+sCgYEAtKFh1y7gVRA4dnxD/xkQHux8HLSCKIWppHKzz6qAMgO0uEbd
F6TJ3d7v3QiAAaGAZYKLTYYZerPGIn3Wy4hwFXtV0JV8SpQhnp9cP//aqI4hX2dO
L8X+vo5n+xp5RrdBfRAUDXiEOObNz6AFm+/9QKuEIotMopJvH83JhFmkNhcCgYEA
qA4V4DGHZPg7Z8dDGtN3tMdyNCpYKpiCjizLWErcdJLpZDq6cQ2kWCaz6OtqTNUQ
Ybn9+CdCmrcrNf3pqnC3jyZK6UkTSyac0uwCoQCXNtbq5SRx/SRV/k/6/o6Kx0ox
Bkh5YYkOBnFIN2zpO523pSip9AQcRRXEfsunZGsX7cMCgYEAgIeTRmV/sotIPqgw
0O98C7jf5EKt8V4BtoB4zEbRLNRrYoDQjVKpUs0KvRhlM+2rDdI8xxX/xqRjtVmB
f4UxC0Ho5ziPwePJkS2+Xtx6+btzqEJM7ygHPLwHeYh7NKHSSGwO8Gy6Iwaaaqke
YQ4kw2ZKzkVNRAFzIKE41fKoRtQ=
-----END PRIVATE KEY-----";

        public IActionResult ShowPrivateKey()
        {
            // Log the private key to demonstrate exposure (not recommended in practice)
            Console.WriteLine($"Private Key: {privateKey}");

            ViewBag.PrivateKey = privateKey;
            return View();
        }


        // Action to send the private key over an insecure HTTP connection
        public async Task<IActionResult> TransmitPrivateKey()
        {
            string url = "http://httpbin.org/post"; // Non-HTTPS URL
            var httpClient = new HttpClient();
            var content = new StringContent(privateKey, Encoding.UTF8, "text/plain");

            // Sending the private key over HTTP
            var response = await httpClient.PostAsync(url, content);

            // Logging the response (not secure)
            ViewBag.Response = await response.Content.ReadAsStringAsync();
            return View();
        }
    }
}
