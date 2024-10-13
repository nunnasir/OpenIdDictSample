using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIdDictSample.Controllers;

[ApiController]
[Route("api/connect")]
public class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly string _secretKey;

    public AuthorizationController(IOpenIddictApplicationManager applicationManager, IConfiguration configuration)
    {
        _applicationManager = applicationManager;
        _secretKey = configuration["JwtSettings:SecretKey"]!;
    }

    [HttpPost("token"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest();

        if (request!.IsClientCredentialsGrantType())
        {
            var application = await _applicationManager.FindByClientIdAsync(request!.ClientId!);
            if (application == null)
            {
                return BadRequest(new OpenIddictResponse
                {
                    Error = Errors.InvalidClient,
                    ErrorDescription = "The specified 'client_id' is invalid."
                });
            }

            if (!await _applicationManager.ValidateClientSecretAsync(application, request!.ClientSecret!))
            {
                return BadRequest(new OpenIddictResponse
                {
                    Error = Errors.InvalidClient,
                    ErrorDescription = "The specified 'client_secret' parameter is invalid."
                });
            }

            var displaName = await _applicationManager.GetDisplayNameAsync(application);

            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
            identity.AddClaim(Claims.Subject, request!.ClientId!);
            identity.AddClaim(Claims.Name, displaName!);

            identity.SetScopes(request.GetScopes());

            foreach (var claim in identity.Claims)
            {
                claim.SetDestinations(claim.Type switch
                {
                    Claims.Name or Claims.Subject => new[] { Destinations.AccessToken, Destinations.IdentityToken },
                    _ => new[] { Destinations.AccessToken }
                });
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = signingCredentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return Ok(new { access_token = tokenString, token_type = "Bearer" });
        }

        return BadRequest(new { Error = "Grant type not supported" });
    }
}
