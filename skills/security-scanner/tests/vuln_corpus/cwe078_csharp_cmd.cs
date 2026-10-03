using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("net")]
public class NetToolsController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping()
    {
        string host = Request.Query["host"];
        var psi = new ProcessStartInfo("cmd.exe");
        psi.Arguments = "/c ping " + host;
        Process.Start(psi);
        return Ok("ok");
    }
}
