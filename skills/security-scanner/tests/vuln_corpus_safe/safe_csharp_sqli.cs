using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("users")]
public class UserController : ControllerBase
{
    private readonly string _connStr;

    public UserController(IConfiguration cfg)
    {
        _connStr = cfg.GetConnectionString("Default");
    }

    [HttpGet("find")]
    public IActionResult Find()
    {
        string name = Request.Query["name"];
        using var conn = new SqlConnection(_connStr);
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        cmd.Parameters.AddWithValue("@name", name);
        conn.Open();
        var reader = cmd.ExecuteReader();
        return Ok(reader);
    }
}
