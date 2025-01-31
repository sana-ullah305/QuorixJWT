using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using VerticalSlice.Models;

namespace VerticalSlice.Controllers;

[ApiController]
[Authorize]
[Route("api/Account")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IConfiguration _configuration;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IHttpContextAccessor httpContextAccessor,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _httpContextAccessor = httpContextAccessor;
        _configuration = configuration;
    }

    // POST: api/Account/Login
    [AllowAnonymous]
    [HttpPost("Login")]
    public async Task<IActionResult> Login(LoginBindingModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            return Unauthorized("Invalid email or password.");
        }
        var roles = await _userManager.GetRolesAsync(user);
        var claims = await _userManager.GetClaimsAsync(user);
        var result = await _signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            return Unauthorized("Invalid email or password.");
        }
        // Generate JWT token
        var token = GenerateJwtToken(user);
        return Ok(new
        {
            Message = "Login successful",
            UserId = user.Id,
            Email = user.Email,
            Token = token
        });
    }

    // GET: api/Account/UserInfo
    [HttpGet("UserInfo")]
    public async Task<IActionResult> GetUserInfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();

        var logins = await _userManager.GetLoginsAsync(user);
        var loginProvider = logins.FirstOrDefault()?.LoginProvider ?? "Local";

        return Ok(new UserInfoViewModel
        {
            UserName = user.UserName,
            Email = user.Email,
            HasRegistered = true,
            LoginProvider = loginProvider
        });
    }

    // POST: api/Account/Logout
    [HttpPost("Logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok();
    }

    // POST: api/Account/ChangePassword
    [HttpPost("ChangePassword")]
    public async Task<IActionResult> ChangePassword(ChangePasswordBindingModel model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();

        var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok();
    }

    // POST: api/Account/SetPassword
    [HttpPost("SetPassword")]
    public async Task<IActionResult> SetPassword(SetPasswordBindingModel model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();

        var result = await _userManager.AddPasswordAsync(user, model.NewPassword);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok();
    }

    // POST: api/Account/Register
    [AllowAnonymous]
    [HttpPost("Register")]
    public async Task<IActionResult> Register(RegisterBindingModel model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok();
    }

    // GET: api/Account/ExternalLogins
    [AllowAnonymous]
    [HttpGet("ExternalLogins")]
    public async Task<IActionResult> GetExternalLogins()
    {
        var externalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync())
            .Select(scheme => new ExternalLoginViewModel
            {
                Name = scheme.Name,
                Url = Url.Action("ExternalLogin", "Account", new { provider = scheme.Name }),
                State = Guid.NewGuid().ToString("N")
            })
            .ToList();

        return Ok(externalLogins);
    }

    // POST: api/Account/RegisterExternal
    [AllowAnonymous]
    [HttpPost("RegisterExternal")]
    public async Task<IActionResult> RegisterExternal(RegisterExternalBindingModel model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null) return BadRequest("Failed to get external login info.");

        var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
        var result = await _userManager.CreateAsync(user);

        if (!result.Succeeded) return BadRequest(result.Errors);

        result = await _userManager.AddLoginAsync(user, info);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok();
    }
    private string GenerateJwtToken(ApplicationUser user)
    {
        var jwtSettings = _configuration.GetSection("Jwt");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpiryInMinutes"])),
            signingCredentials: credentials
        );
        var _key = new byte[32]; // 256 bits
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(_key);
        }
        var base64Key = Convert.ToBase64String(_key);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}