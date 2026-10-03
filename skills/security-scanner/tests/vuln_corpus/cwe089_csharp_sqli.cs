using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("users")]
public class UserController : ControllerBase
{
    private const string ConnStr = "Server=db;Database=app;Trusted_Connection=True;";

    [HttpGet("find")]
    public IActionResult Find()
    {
        string name = Request.Query["name"];
        using var conn = new SqlConnection(ConnStr);
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
        conn.Open();
        var reader = cmd.ExecuteReader();
        return Ok(reader);
    }
}
