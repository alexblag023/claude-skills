using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("integration")]
public class PaymentController : ControllerBase
{
    private readonly string _apiKey;

    public PaymentController(IConfiguration cfg)
    {
        // Секрет берётся из конфигурации/секрет-хранилища, не из кода.
        _apiKey = cfg["Payment:ApiKey"];
    }

    [HttpPost("charge")]
    public IActionResult Charge(decimal amount)
    {
        var client = new PaymentGateway(_apiKey);
        client.Charge(amount);
        return Ok();
    }
}
