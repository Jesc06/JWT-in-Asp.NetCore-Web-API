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

```json
  "Jwt": {
    "key": "AspDotnet_Core_Clean_Architecture_Dotnet_nine",
    "Issuer": "RecordManagementSystem",
    "Audience": "Users",
    "DurationInMinutes": 1,
    "RefreshTokenDurationInMinutes": 2
  },
```

---

| Setting          | Description                                    |
|------------------|-----------------------------------------------|
| **key**          | Secret key for signing tokens – keep it safe! |
| **Issuer**       | Who issues the token (your API).              |
| **Audience**     | Who can use the token (your clients/users).   |
| **ExpireMinutes**| Token lifetime in minutes.                    |

📂 **File location:** root folder of your Web API project.

---



## 4️⃣ Create DTOs

### `GenerateTokenDTO`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RecordManagementSystem.Application.Features.Account.DTO
{
    public class JwtApplicationUserDTO
    {
        public string id { get; set; }
        public string username { get; set; }
        public string email { get; set; }
        public IList<string> Roles { get; set; } = new List<string>();
    }
}   


```

### `GenerateJwtTokenResponseDTO`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RecordManagementSystem.Application.Features.Account.DTO
{
    public class GenerateJwtTokenResponseDTO
    {
        public string AccessToken { get; set; } 
        public string RefreshToken { get; set; }
    }
}


```

### `JwtRefreshTokenResponseDTO`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RecordManagementSystem.Application.Features.Account.DTO
{
    public class JwtRefreshTokenRequestDTO
    {
        public string newAccessToken { get; set; }
        public string newRefreshToken { get; set; }
    }
}

```

### `JwtRefreshTokenRequestDTO`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RecordManagementSystem.Application.Features.Account.DTO
{
    public class JwtRefreshTokenRequestDTO
    {
        public string newAccessToken { get; set; }
        public string newRefreshToken { get; set; }
    }
}

```

<br>


## 3️⃣ Create `JWTService` (Infrastructure Layer)

Generates JWT + Refresh tokens when user logs in.

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using RecordManagementSystem.Application.Features.Account.Interface;
using RecordManagementSystem.Application.Features.Account.DTO;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace RecordManagementSystem.Infrastructure.Services
{
    public class JwtService : IJwtToken
    {
        private readonly IConfiguration _configuration;
        private readonly Byte[] _key;
        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
            _key = Encoding.UTF8.GetBytes(_configuration["Jwt:key"]!);
        }

        public string GenerateAccessJwtToken(GenerateTokenDTO user, IEnumerable<Claim>? additionalClaims = null)
        {
            var duration = double.Parse(_configuration["Jwt:DurationInMinutes"] ?? "1");

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.username ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("uid", user.id.ToString())
            };
            if (user.Roles != null)
                claims.AddRange(user.Roles.Select(r => new Claim("role", r)));

            if (additionalClaims != null)
                claims.AddRange(additionalClaims);

            var credentials = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(duration),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateRefreshJwtToken()
        {
            var bytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        public string HashRefreshToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            return Convert.ToBase64String(sha256.ComputeHash(bytes));
        }

        public bool VerfiyHashedJwtToken(string hash, string token)
        {
            return hash == HashRefreshToken(token);
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredJwtToken(string token)
        {
            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(_key),
                ValidateLifetime = false // allow expired token to get claims
            };

            var handler = new JwtSecurityTokenHandler();
            try
            {
                var principal = handler.ValidateToken(token, validationParams, out var securityToken);
                if (securityToken is not JwtSecurityToken jwt ||
                    !jwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                    return null;
                return principal;
            }
            catch
            {
                return null;
            }
        }
    }
}

```


## 7️⃣ `Implementing JWTService in AuthService`

```csharp
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RecordManagementSystem.Application.Common.Models;
using RecordManagementSystem.Application.Features.Account.DTO;
using RecordManagementSystem.Application.Features.Account.Interface;
using RecordManagementSystem.Infrastructure.Persistence.Data;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace RecordManagementSystem.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly SignInManager<UserIdentity> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly UserManager<UserIdentity> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IJwtToken _jwtToken;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AuthService(SignInManager<UserIdentity> signInManager, 
                           UserManager<UserIdentity> userManager,
                           ApplicationDbContext context,
                           RoleManager<IdentityRole> roleManager,
                           IJwtToken jwtToken,
                           IConfiguration configuration)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _context = context;
            _roleManager = roleManager;
            _jwtToken = jwtToken;
            _configuration = configuration;
        }
        public async Task<GenerateJwtTokenResponseDTO> Login(LoginDTO loginDTO)
        {
            var findUser = await _userManager.FindByEmailAsync(loginDTO.Email);
            if (findUser is null) return null;

            var isLogin = await _userManager.CheckPasswordAsync(findUser, loginDTO.Password);
            if (!isLogin) return null;

            var getUserRoles = await _userManager.GetRolesAsync(findUser);

            GenerateTokenDTO user = new GenerateTokenDTO
            {
                id = findUser.Id,
                username = findUser.UserName,
                email = findUser.Email,
                Roles = getUserRoles
            };

            var accessToken = _jwtToken.GenerateAccessJwtToken(user);
            var refreshToken = _jwtToken.GenerateRefreshJwtToken();

    
            var refreshTokenDurationMinutes = int.Parse(_configuration["Jwt:RefreshTokenDurationInMinutes"] ?? "2");
            findUser.RefreshTokenHash = _jwtToken.HashRefreshToken(refreshToken);
            findUser.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(refreshTokenDurationMinutes);

            await _userManager.UpdateAsync(findUser);

            return new GenerateJwtTokenResponseDTO
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public async Task<Result<JwtRefreshTokenResponseDTO>> JwtRefreshToken(JwtRefreshTokenRequestDTO tokenRequest)
        {
            var principal = _jwtToken.GetPrincipalFromExpiredJwtToken(tokenRequest.newAccessToken);
            if (principal is null)
                return Result<JwtRefreshTokenResponseDTO>.Fail("Principal is null");

            var username = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                           ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? principal.FindFirst("name")?.Value;

            if (username is null)
                return Result<JwtRefreshTokenResponseDTO>.Fail("Cannot find username in token");

            // Fetch user
            var user = await _userManager.Users.AsNoTracking().FirstOrDefaultAsync(u => u.UserName == username);
            if (user is null)
                return Result<JwtRefreshTokenResponseDTO>.Fail("User not found");

            // Check if refresh token expired
            if (!user.RefreshTokenExpiryTime.HasValue || user.RefreshTokenExpiryTime.Value <= DateTime.UtcNow)
                return Result<JwtRefreshTokenResponseDTO>.Fail("Refresh token expired");

            // Verify refresh token hash
            bool isValidRefreshToken = _jwtToken.VerfiyHashedJwtToken(user.RefreshTokenHash, tokenRequest.newRefreshToken);
            if (!isValidRefreshToken)
                return Result<JwtRefreshTokenResponseDTO>.Fail("Invalid or reused refresh token");

            //Optional: enforce single-use (invalidate after 1 refresh)
            var trackedUser = await _userManager.FindByIdAsync(user.Id);
            trackedUser.RefreshTokenHash = null;
            trackedUser.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(trackedUser);

            //Generate new access token only (no new refresh token)
            var roles = await _userManager.GetRolesAsync(user);
            var newAccessToken = _jwtToken.GenerateAccessJwtToken(new GenerateTokenDTO
            {
                id = user.Id,
                username = user.UserName,
                email = user.Email,
                Roles = roles
            });

            return Result<JwtRefreshTokenResponseDTO>.Ok(new JwtRefreshTokenResponseDTO
            {
                newAccessToken = newAccessToken,
                newRefreshToken = tokenRequest.newRefreshToken
            });
        }


        public async Task Logout()
        {
            var user = await _userManager.FindByEmailAsync("your login user email or username");
            if (user is  not null)
            {
                user.RefreshTokenHash = null;
                user.RefreshTokenExpiryTime = null;
                await _userManager.UpdateAsync(user);

                await _signInManager.SignOutAsync();
            }
        }

    }
}

```


---

## 7️⃣ Configure Authentication in `Program.cs`

```csharp

//JWT token configuration
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["key"]!);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key),
            RoleClaimType = ClaimTypes.Role,

            ClockSkew = TimeSpan.Zero // remove 5 minutes grace
            //kase kahit 1 minute na yung JWT token automatic may palugit na additional 5 minutes or 6 minutes bago tuluyan mawala
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
