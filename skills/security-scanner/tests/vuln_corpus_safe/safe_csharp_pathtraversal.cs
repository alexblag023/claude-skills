using System.IO;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("files")]
public class FilesController : ControllerBase
{
    private const string Root = @"C:\app\data\";

    [HttpGet("download")]
    public IActionResult Download()
    {
        // Отбрасываем любые сегменты пути, оставляя только имя файла.
        string file = Path.GetFileName(Request.Query["file"]);
        string content = File.ReadAllText(Path.Combine(Root, file));
        return Content(content);
    }
}
