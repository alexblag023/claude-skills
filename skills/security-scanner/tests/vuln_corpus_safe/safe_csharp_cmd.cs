using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("net")]
public class NetToolsController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping()
    {
        // Валидируем ввод и передаём как отдельный аргумент фиксированной программе, без оболочки.
        if (!IPAddress.TryParse(Request.Query["host"], out var ip))
            return BadRequest("invalid host");
        var psi = new ProcessStartInfo("ping");
        psi.ArgumentList.Add("-n");
        psi.ArgumentList.Add("1");
        psi.ArgumentList.Add(ip.ToString());
        Process.Start(psi);
        return Ok("ok");
    }
}
