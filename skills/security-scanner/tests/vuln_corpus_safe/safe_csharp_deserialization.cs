using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("state")]
public class StateController : ControllerBase
{
    public record AppState(string Name, int Level);

    [HttpPost("restore")]
    public IActionResult Restore()
    {
        // System.Text.Json не привязывает типы из данных — тип задан статически.
        string json = Request.Form["blob"];
        AppState state = JsonSerializer.Deserialize<AppState>(json);
        return Ok(state.Name);
    }
}
