using Microsoft.AspNetCore.Identity;

namespace OpenIdDictSample;

public class IdentitySeeder : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public IdentitySeeder(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        var adminEmail = "nasiru.bs23@gmail.com";
        var adminPassword = "123456@Aa";

        if (await userManager.FindByEmailAsync(adminEmail) == null)
        {
            var adminUser = new IdentityUser
            {
                Email = adminEmail,
                UserName = adminEmail,
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(adminUser, adminPassword);

            if (!result.Succeeded)
            {
                throw new Exception("User creation failed: " + string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                var roleResult =await roleManager.CreateAsync(new IdentityRole("Admin"));

                if (!roleResult.Succeeded)
                {
                    throw new Exception("Role creation failed: " + string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                }
            }

            var addToRoleResult = await userManager.AddToRoleAsync(adminUser, "Admin");

            if (!addToRoleResult.Succeeded)
            {
                // Log the error if role assignment failed
                throw new Exception("Adding user to role failed: " + string.Join(", ", addToRoleResult.Errors.Select(e => e.Description)));
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

