# 🔑 JWT Authentication Setup (ASP.NET Core Web API)

This guide shows you **step by step** how to add **JWT Authentication** to an ASP.NET Core Web API project using **Clean Architecture** (Application + Infrastructure layers).  
No prior JWT experience required. 🚀

---

## 1️⃣ Install Required NuGet Packages

Run these commands in your terminal:

```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package System.IdentityModel.Tokens.Jwt
```

✅ These packages let you **create** and **validate** JWT tokens.

---

## 2️⃣ Add JWT Settings to `appsettings.json`

```jsonc
"Jwt": {
  "key": "AspDotnet_Core_Clean_Architecture_Dotnet_nine",
  "Issuer": "RecordManagementSystem",
  "Audience": "Users",
  "ExpireMinutes": 60
}
```

| Setting          | Description                                    |
|------------------|-----------------------------------------------|
| **key**          | Secret key for signing tokens – keep it safe! |
| **Issuer**       | Who issues the token (your API).              |
| **Audience**     | Who can use the token (your clients/users).   |
| **ExpireMinutes**| Token lifetime in minutes.                    |

📂 **File location:** root folder of your Web API project.

---

## 3️⃣ Create `GenerateTokenService` (Infrastructure Layer)

Generates JWT + Refresh tokens when user logs in.

```csharp
// Infrastructure/Services/GenerateTokenService.cs
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using RecordManagementSystem.Application.Features.Account.DTO;
using RecordManagementSystem.Application.Features.Account.Interface;

namespace RecordManagementSystem.Infrastructure.Services;

public class GenerateTokenService : IGenerateTokenService
{
    private readonly IConfiguration _config;
    public GenerateTokenService(IConfiguration config) => _config = config;

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
        var expiration = DateTime.UtcNow.AddMinutes(double.Parse(_config["Jwt:ExpireMinutes"]));

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
            Role = role,
            RefreshToken = GenerateRefreshToken(),
            RefreshTokenExpiry = DateTime.UtcNow.AddDays(7)
        };
    }

    private static string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }
}
```

---

## 4️⃣ Create DTOs

### `TokenResponseDTO`
```csharp
namespace RecordManagementSystem.Application.Features.Account.DTO;

public class TokenResponseDTO
{
    public string Token { get; set; }
    public int ExpiresIn { get; set; }
    public string Role { get; set; }

    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiry { get; set; }
}
```

### `RefreshTokenDTO`
```csharp
namespace RecordManagementSystem.Application.Features.Account.DTO;

public class RefreshTokenDTO
{
    public string RefreshToken { get; set; }
}
```

---

## 4️⃣ Create Refresh Token Entity and DbContext

### `RefreshToken` Entity
```csharp
namespace RecordManagementSystem.Domain.Entities.Token
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Token { get; set; }
        public DateTime ExpiryDate { get; set; }
        public bool IsRevoked { get; set; }
    }
}
```

### `ApplicationDbContext`
```csharp
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using RecordManagementSystem.Domain.Entities.Account;
using RecordManagementSystem.Domain.Entities.Token;

namespace RecordManagementSystem.Infrastructure.Persistence.Data
{
    public class ApplicationDbContext : IdentityDbContext<UserIdentity>
    {
        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
```

---

## 5️⃣ Create `RefreshTokenService` (Infrastructure Layer)

Handles saving and updating refresh tokens in the database.

```csharp
using Microsoft.EntityFrameworkCore;
using RecordManagementSystem.Application.Features.Account.Interface;
using RecordManagementSystem.Domain.Entities.Token;
using RecordManagementSystem.Infrastructure.Persistence.Data;

namespace RecordManagementSystem.Infrastructure.Services;

public class RefreshTokenService : IRefreshToken
{
    private readonly ApplicationDbContext _context;
    public RefreshTokenService(ApplicationDbContext context) => _context = context;

    public async Task AddAsync(RefreshToken refreshToken)
    {
        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
    }

    public async Task<RefreshToken?> GetByTokenAsync(string token) =>
        await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == token && !x.IsRevoked);

    public async Task UpdateAsync(RefreshToken refreshToken)
    {
        _context.RefreshTokens.Update(refreshToken);
        await _context.SaveChangesAsync();
    }
}
```

---

## 6️⃣ Use Token Service in `AuthService` (Application Layer)

```csharp
public async Task<TokenResponseDTO> Login(LoginDTO loginDTO)
{
    var isLogin = await _authService.Login(loginDTO);
    if (!isLogin) throw new UnauthorizedAccessException("Invalid credentials!");

    var token = _generateTokenService.GenerateToken(loginDTO.Email, "Student");

    await _refreshToken.AddAsync(new RefreshToken
    {
        Username = loginDTO.Email,
        Token = token.RefreshToken,
        ExpiryDate = token.RefreshTokenExpiry,
        IsRevoked = false
    });

    return token;
}

public async Task<TokenResponseDTO> RefreshToken(RefreshTokenDTO refreshTokenDTO)
{
    var savedToken = await _refreshToken.GetByTokenAsync(refreshTokenDTO.RefreshToken);
    if (savedToken is null || savedToken.ExpiryDate < DateTime.UtcNow)
        throw new UnauthorizedAccessException("Invalid or expired refresh token");

    var newTokens = _generateTokenService.GenerateToken(savedToken.Username, "Student");
    savedToken.Token = newTokens.RefreshToken;
    savedToken.ExpiryDate = newTokens.RefreshTokenExpiry;
    await _refreshToken.UpdateAsync(savedToken);

    return newTokens;
}
```

---

## 7️⃣ Configure Authentication in `Program.cs`

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
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings["key"]))
    };
});

builder.Services.AddAuthorization();
```

Enable middleware:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

---

✅ **Done!**  
Your API is now secured with **JWT authentication + refresh tokens**.  
You can test it by logging in, getting a token, and calling a `[Authorize]` endpoint.
