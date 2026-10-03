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
        string file = Request.Query["file"];
        string content = File.ReadAllText(Path.Combine(Root, file));
        return Content(content);
    }
}
