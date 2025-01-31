using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using VerticalSlice.Models;

namespace VerticalSlice.Providers;

public class ApplicationOAuthEvents : OAuthEvents
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public ApplicationOAuthEvents(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    public override async Task CreatingTicket(OAuthCreatingTicketContext context)
    {
        var email = context.Principal.FindFirstValue(ClaimTypes.Email);
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
        {
            // Create a new user if not found
            user = new ApplicationUser { UserName = email, Email = email };
            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                context.Fail("Failed to create user.");
                return;
            }
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Email, user.Email)
        };

        var identity = new ClaimsIdentity(claims, context.Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var authProperties = new AuthenticationProperties();

        await _signInManager.SignInWithClaimsAsync(user, authProperties, claims);
        context.RunClaimActions();
    }
}