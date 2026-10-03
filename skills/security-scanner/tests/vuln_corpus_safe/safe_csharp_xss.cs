using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("search")]
public class SearchController : ControllerBase
{
    [HttpGet("echo")]
    public async Task Echo()
    {
        string q = Request.Query["q"];
        Response.ContentType = "text/html";
        // Кодируем ввод перед вставкой в HTML.
        string safe = HtmlEncoder.Default.Encode(q);
        await Response.WriteAsync("<h1>Results for " + safe + "</h1>");
    }
}
