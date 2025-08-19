# JWT Authentication Setup in ASP.NET Core Web API

This guide explains step-by-step how to set up **JWT Authentication** in an ASP.NET Core Web API project using **Clean Architecture** (with Infrastructure and Application layers). It’s beginner-friendly and assumes no prior deep knowledge of JWT.

---

## 1. Install Required Packages

Make sure you have installed these NuGet packages:

```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package System.IdentityModel.Tokens.Jwt
```

These packages are necessary for JWT token creation and authentication.

---

## 2. Configure JWT Settings in `appsettings.json`

Add a section for JWT settings in your `appsettings.json` file:

```json
"Jwt": {
  "key": "AspDotnet_Core_Clean_Architecture_Dotnet_nine",
  "Issuer": "RecordManagementSystem",
  "Audience": "Users",
  "ExpireMinutes": 60
}
```

- **key**: Secret key used to sign the token (keep it safe!).
- **Issuer**: The entity that issues the token (usually your API).
- **Audience**: Who the token is intended for (clients/users).
- **ExpireMinutes**: Token expiration time in minutes.

---

## 3. Create the `GenerateTokenService` in Infrastructure Layer

This service will generate JWT tokens when a user logs in.

```csharp
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using RecordManagementSystem.Application.Features.Account.DTO;
using RecordManagementSystem.Application.Features.Account.Interface;

namespace RecordManagementSystem.Infrastructure.Services
{
    public class GenerateTokenService : IGenerateTokenService
    {
        private readonly IConfiguration _config;

        public GenerateTokenService(IConfiguration config)
        {
            _config = config;
        }

        public TokenResponseDTO GenerateToken(string username, string role)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(ClaimTypes.Role, role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiration = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_config["Jwt:ExpireMinutes"]));

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: expiration,
                signingCredentials: creds
            );

            return new TokenResponseDTO
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                ExpiresIn = (int)(expiration - DateTime.UtcNow).TotalSeconds,
                Role = role
            };
        }
    }
}
```

---

## 4. Call the Token Service in Application Layer

In your **AuthService** (or wherever you handle login):

```csharp
public async Task<TokenResponseDTO> Login(LoginDTO loginDTO)
{
    var isLogin = await _authService.Login(loginDTO);
    if (isLogin)
    {
        // Generate token for the user
        var token = _generateTokenService.GenerateToken(loginDTO.Email, "Student");
        return token;
    }

    throw new UnauthorizedAccessException("Invalid credentials!");
}
```

---

## 5. Configure Authentication in `Program.cs` (or `Startup.cs`)

Add JWT authentication to the DI container:

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var jwtSettings = builder.Configuration.GetSection("Jwt");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["key"]))
    };

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            // Support for JWT in cookies (optional)
            if (context.Request.Cookies.ContainsKey("Jwt"))
            {
                context.Token = context.Request.Cookies["Jwt"];
            }
            return Task.CompletedTask;
        }
    };
});
```

---

## 6. Enable Authentication Middleware

Make sure you add authentication and authorization middleware in the request pipeline:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

