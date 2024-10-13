using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace OpenIdDictSample.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly IConfiguration _configuration;

    public AuthController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IOpenIddictTokenManager tokenManager, IConfiguration configuration)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenManager = tokenManager;
        _configuration = configuration;
    }

    [HttpPost("token")]
    public async Task<IActionResult> Token([FromForm] string username, [FromForm] string password)
    {
        if (!ModelState.IsValid) return BadRequest();

        var user = await _userManager.FindByNameAsync(username);
        if (user == null) return Unauthorized();

        var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
        if (!result.Succeeded)
        {
            if (result.IsLockedOut) return Unauthorized(new { message = "User is locked out" });
            if (result.IsNotAllowed) return Unauthorized(new { message = "User is not allowed to sign in" });
            if (result.RequiresTwoFactor) return Unauthorized(new { message = "Requires two-factor authentication" });

            return Unauthorized(new { message = "Invalid password" });
        }

        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        var identity = (ClaimsIdentity)principal.Identity!;
        identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, user.Id));
        identity.AddClaim(new Claim(OpenIddictConstants.Claims.Email, user.Email!));

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        }

        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"]!);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = identity,
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var tokenString = jwtTokenHandler.WriteToken(token);

        return Ok(new
        {
            access_token = tokenString,
            token_type = OpenIddictConstants.TokenTypes.Bearer,
            expires_in = 3600
        });
    }
}
