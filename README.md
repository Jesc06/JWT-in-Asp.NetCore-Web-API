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

### `JwtPayloadDTO`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KapeRest.Application.DTOs.Jwt
{
    public class JwtPayloadDTO
    {
        public string id { get; set; }
        public string username { get; set; }
        public string email { get; set; }
        public IList<string> roles { get; set; }
    }
}


```

### `CreateJwtTokenDTO`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KapeRest.Application.DTOs.Jwt
{
    public class CreateJwtTokenDTO
    {
        public string token { get; set; }
        public string refreshToken { get; set; }    
    }
}



```

### `JwtRefreshResponseDTO`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KapeRest.Application.DTOs.Jwt
{
    public class JwtRefreshResponseDTO
    {
        public string responseToken { get; set; }
        public string responseRefreshToken { get; set; }
    }
}


```

### `JwtRefreshRequestDTO`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KapeRest.Application.DTOs.Jwt
{
    public class JwtRefreshRequestDTO
    {
        public string requestToken { get; set; }    
        public string requestRefreshToken { get; set; }
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
using KapeRest.Application.Interfaces.Jwt;
using Microsoft.Extensions.Configuration;
using KapeRest.Application.DTOs.Jwt;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Runtime.Intrinsics.Arm;
using System.Net.Http.Headers;

namespace KapeRest.Infrastructures.Services.JwtService
{
    public class GenerateToken : IJwtService
    {
        private readonly IConfiguration _config;
        private readonly Byte[] _key;
        public GenerateToken(IConfiguration config)
        {
            _config = config;
            _key = Encoding.UTF8.GetBytes(_config["Jwt:key"]!);
        }

        public string CreateToken(JwtPayloadDTO payload, IEnumerable<Claim>? additionalClaim = null)
        {
            var expiry = double.Parse(_config["Jwt:TokenDurationInMinutes"] ?? "1");

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, payload.username ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("uid", payload.id.ToString()),
                new Claim(ClaimTypes.Email, payload.email ?? ""),
                new Claim(ClaimTypes.NameIdentifier, payload.id.ToString())
            };

            if (payload.roles != null)
                claims.AddRange(payload.roles.Select(r => new Claim(ClaimTypes.Role, r)));

            if (additionalClaim != null)
                claims.AddRange(additionalClaim);

            var credentials = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiry),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string RefreshToken()
        {
            var bytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        public string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            return Convert.ToBase64String(sha256.ComputeHash(bytes));
        }

        public bool VerifyHashedToken(string hashedToken, string token)
        {
            return hashedToken == HashToken(token);
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = _config["Jwt:Issuer"],
                ValidAudience = _config["Jwt:Audience"],
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
            catch { return null; }
        }


    }
}


```


## 7️⃣ `Implementing JWTService in Repositories`

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KapeRest.Application.Interfaces.Account;
using KapeRest.Infrastructures.Persistence.Database;
using Microsoft.AspNetCore.Identity;
using KapeRest.Application.DTOs.Account;
using Microsoft.Extensions.Configuration;
using KapeRest.Application.Interfaces.Jwt;
using KapeRest.Application.DTOs.Jwt;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;

namespace KapeRest.Infrastructures.Persistence.Repositories.Account
{
    public class RegisterAccountRepositories : IAccounts
    {
        private readonly UserManager<Users> _userManager;
        private readonly SignInManager<Users> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _config;
        private readonly IJwtService _jwtService;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public RegisterAccountRepositories(
                UserManager<Users> userManager,
                SignInManager<Users> signInManager,
                ApplicationDbContext context,
                RoleManager<IdentityRole> roleManager,
                IConfiguration config,
                IJwtService jwtService,
                IHttpContextAccessor httpContextAccessor
                )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _roleManager = roleManager;
            _config = config;
            _jwtService = jwtService;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<bool> RegisterAccount(RegisterAccountDTO register)
        {
            var users = new Users
            {
                FirstName = register.FirstName,
                MiddleName = register.MiddleName,
                LastName = register.LastName,
                UserName = register.Email,
                Email = register.Email,
            };
            var registerUser = await _userManager.CreateAsync(users, register.Password);
            if (registerUser.Succeeded)
            {
                if(register.Roles.Equals("Admin",StringComparison.InvariantCultureIgnoreCase))
                    throw new Exception("Cannot assign Admin role during registration.");

                await _userManager.AddToRoleAsync(users, register.Roles);
                return true;
            }
            return false;
        }

        public async Task<CreateJwtTokenDTO> Login(LoginDTO login)
        {
            var user = await _userManager.FindByEmailAsync(login.Email);
            if (user == null) return null;

            var isLogin = await _userManager.CheckPasswordAsync(user, login.Password);
            if (!isLogin) return null;

            var getUserRoles = await _userManager.GetRolesAsync(user);

            var payload = new JwtPayloadDTO
            {
                id = user.Id,
                username = user.UserName,
                email = user.Email,
                roles = getUserRoles
            };

            var token = _jwtService.CreateToken(payload);
            var refreshToken = _jwtService.RefreshToken();

            var tokenExpiry = int.Parse(_config["Jwt:TokenDurationInMinutes"] ?? "1");
            user.RefreshTokenHash = _jwtService.HashToken(refreshToken);
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(tokenExpiry);

            await _userManager.UpdateAsync(user);   

            return new CreateJwtTokenDTO
            {
                token =  token,
                refreshToken = refreshToken
            };

        }

        public async Task<JwtRefreshResponseDTO> RefreshToken(JwtRefreshRequestDTO requestDTO)
        {
            var principal = _jwtService.GetPrincipalFromExpiredToken(requestDTO.requestToken);
            if (principal is null)
                return null;

            var username = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                           ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? principal.FindFirst("name")?.Value;

            if(username is null)
                return null;

            var user = await _userManager.Users.AsNoTracking().FirstOrDefaultAsync(u => u.UserName == username);
            if (user is null)
                return null;

            if(!user.RefreshTokenExpiryTime.HasValue || user.RefreshTokenExpiryTime.Value <= DateTime.UtcNow)
                return null;

            bool isValidRefreshToken = _jwtService.VerifyHashedToken(user.RefreshTokenHash ?? "", requestDTO.requestRefreshToken);
            if (!isValidRefreshToken)
                return null;

            var trackUser = await _userManager.FindByIdAsync(user.Id);
            trackUser.RefreshTokenHash = null;
            trackUser.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(trackUser);

            var roles = await _userManager.GetRolesAsync(user);
            var newToken = _jwtService.CreateToken(new JwtPayloadDTO
            {
                id = user.Id,
                username = user.UserName,
                email = user.Email,
                roles = roles
            });

            return new JwtRefreshResponseDTO
            {
                responseToken = newToken,
                responseRefreshToken = requestDTO.requestRefreshToken
            };


        }



    }
}


```

## 7️⃣ `Implementing Logout in Repositories`

### `ICurrentUser`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KapeRest.Application.Interfaces.CurrentUserService
{
    public interface ICurrentUser
    {
        string? Email { get; }
        string? UserId { get; }
    }
}

```

---

### `CurrentUserService`
```csharp
using KapeRest.Application.Interfaces.CurrentUserService;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace KapeRest.Infrastructures.Services.CurrentUserService
{
    public class CurrentUserService : ICurrentUser
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        public CurrentUserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public string? Email => _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.Email);
        public string? UserId => _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier);
    }
}


```

---


### `Auth Repositories`
```csharp
       public async Task Logout(string username)
       {
           var user = await _userManager.FindByNameAsync(username);
           if (user == null) return;

           user.RefreshTokenHash = null;
           user.RefreshTokenExpiryTime = null;
           await _userManager.UpdateAsync(user);
       }
```

---

### `Auth Application Service`
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KapeRest.Application.Interfaces.Account;
using KapeRest.Application.DTOs.Account;
using KapeRest.Application.DTOs.Jwt;
using KapeRest.Application.Interfaces.CurrentUserService;

namespace KapeRest.Application.Services.Account
{
    public class AccountService
    {
        private IAccounts _accountRepository;
        private ICurrentUser _currentUser;
        public AccountService(IAccounts accountRepository, ICurrentUser currentUser)
        {
            _accountRepository = accountRepository;
            _currentUser = currentUser;
        }

        public async Task Logout()
        {
            var email = _currentUser.Email;
            if (string.IsNullOrEmpty(email))
                throw new Exception("User is not logged in.");

            await _accountRepository.Logout(email);
        }
    }
}

```

## 7️⃣ Configure Authentication in `Program.cs`

```csharp

#region --JWT Authentication--
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
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:key"])),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero // remove 5 minutes grace
    };
});

builder.Services.AddAuthorization();
#endregion
```

Enable middleware:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

---

# `Enable Authorize UI in Swagger`

```csharp
builder.Services.AddSwaggerGen(options =>
{
    var jwtSecurityScheme = new OpenApiSecurityScheme
    {
        BearerFormat = "JWT",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = JwtBearerDefaults.AuthenticationScheme,
        Description =  "Enter your JWT Access Token",
        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme
        }
    };

    options.AddSecurityDefinition("Bearer", jwtSecurityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { jwtSecurityScheme, Array.Empty<string>() }
    });

});
```

---


✅ **Done!**  
Your API is now secured with **JWT authentication + refresh tokens**.  
You can test it by logging in, getting a token, and calling a `[Authorize]` endpoint.
