using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("integration")]
public class PaymentController : ControllerBase
{
    private const string ApiKey = "EXAMPLE-dummy-not-a-real-key-000";

    [HttpPost("charge")]
    public IActionResult Charge(decimal amount)
    {
        var client = new PaymentGateway(ApiKey);
        client.Charge(amount);
        return Ok();
    }
}
