using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("state")]
public class StateController : ControllerBase
{
    [HttpPost("restore")]
    public IActionResult Restore()
    {
        var bytes = Convert.FromBase64String(Request.Form["blob"]);
        using var ms = new MemoryStream(bytes);
        var formatter = new BinaryFormatter();
        object obj = formatter.Deserialize(ms);
        return Ok(obj.ToString());
    }
}
