using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("auth")]
public class HashController : ControllerBase
{
    [HttpPost("hash")]
    public IActionResult Hash([FromForm] string password)
    {
        using var md5 = MD5.Create();
        byte[] digest = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Ok(Convert.ToHexString(digest));
    }
}
