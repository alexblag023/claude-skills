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
        await Response.WriteAsync("<h1>Results for " + q + "</h1>");
    }
}
