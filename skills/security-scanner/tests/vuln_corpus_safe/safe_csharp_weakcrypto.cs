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
        // PBKDF2 со случайной солью для хранения паролей.
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] digest = Rfc2898DeriveBytes.Pbkdf2(
            password, salt, 310000, HashAlgorithmName.SHA256, 32);
        return Ok(Convert.ToHexString(digest));
    }
}
