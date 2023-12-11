using LocacaoDeCarros.Identity.API.Models;
using LocacaoDeCarros.Identity.API.Repositories;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using static LocacaoDeCarros.Identity.API.Models.UserResponse;

namespace LocacaoDeCarros.Identity.API.Services
{
    public interface IIdentityService
    {
        Task<UserResponse> GetUserResponse(string email);
        Task<UserResponse> Register(UserRegister userRegister);
        Task<UserResponse> Login(UserLogin userLogin);
        Task Logout();
        Task ResetPassword(IdentityUser user, string token, string newPassword);
        Task<string> GenerateResetPasswordToken(IdentityUser user);
        Task<IdentityUser> GetUserByEmail(string email);
        Task<IdentityUser> GetUserById(string id);
        Task<RefreshToken> GetRefreshToken(Guid token);
    }

    public class IdentityService : IIdentityService
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly TokenAppSettings _tokenAppSettings;
        private readonly IJwtService _jwtService;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public IdentityService(UserManager<IdentityUser> userManager,
                               SignInManager<IdentityUser> signInManager,
                               IOptions<TokenAppSettings> tokenAppSettings,
                               IJwtService jwtService,
                               IRefreshTokenRepository refreshTokenRepository)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _tokenAppSettings = tokenAppSettings.Value;
            _jwtService = jwtService;
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task<string> GenerateResetPasswordToken(IdentityUser user)
        {
            var result = await _userManager.GeneratePasswordResetTokenAsync(user);
            return result;
        }

        public async Task<UserResponse> Login(UserLogin userLogin)
        {
            var result = await _signInManager.PasswordSignInAsync(userLogin.Email, userLogin.Password,
                false, true);

            if (!result.Succeeded)
                throw new InvalidOperationException("Não foi possível realizar o login.");

            if (result.IsLockedOut)
                throw new UnauthorizedAccessException("Seu usuário ainda está bloqueado por excesso de tentativas de login. Tente novamente mais tarde.");

            var loginResponse = await GetUserResponse(userLogin.Email);
            return loginResponse;
        }

        public async Task Logout()
        {
            await _signInManager.SignOutAsync();
        }

        public async Task<UserResponse> Register(UserRegister userRegister)
        {
            var newUser = new IdentityUser
            {
                Email = userRegister.Email,
                UserName = userRegister.Email, 
                EmailConfirmed = false, 
                PhoneNumber = userRegister.Telefone
            };

            var result = await _userManager.CreateAsync(newUser, userRegister.Senha);

            if (!result.Succeeded)
                throw new InvalidOperationException("Falha ao registrar o usuário! Tente novamente mais tarde.");

            var registerResponse = await GetUserResponse(userRegister.Email);
            return registerResponse;
        }

        public async Task ResetPassword(IdentityUser user, string token, string newPassword)
        {
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

            if (result.Succeeded)
                await Task.CompletedTask;

            throw new InvalidOperationException("Não foi possível atualizar sua senha! Tente novamente mais tarde.");
        }

        public async Task<IdentityUser> GetUserByEmail(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user is null)
                throw new InvalidOperationException("Não foi encontrado nenhum usuário cadastrado com esse email.");

            return user;
        }

        public async Task<IdentityUser> GetUserById(string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user is null) throw new InvalidOperationException("Nenhum usuário foi encontrado!");

            return user;
        }

        public async Task<RefreshToken> GetRefreshToken(Guid token)
        {
            var refreshToken = await _refreshTokenRepository.GetRefreshToken(token);

            if (refreshToken.ExpirationDate.ToLocalTime() < DateTime.UtcNow)
                return null;
            return refreshToken;
        }

        public async Task<UserResponse> GetUserResponse(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(user);

            await BuildUserClaims(claims, user);

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims);

            var userResponse = new UserResponse()
            {
                AccessToken = await GenerateJwt(claimsIdentity), 
                ExpiresIn = TimeSpan.FromHours(_tokenAppSettings.ExpiresIn).TotalSeconds, 
                RefreshToken = await GenerateRefreshToken(user.Email),
                User = new UserToken
                {
                    Id = Guid.Parse(user.Id), 
                    Email = user.Email, 
                    Claims = claims.Select(claim => new UserClaim
                    {
                        Type = claim.Type,
                        Value = claim.Value
                    })
                }
            };

            return userResponse;
        }


        private async Task BuildUserClaims(IList<Claim> claims, IdentityUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Exp, DateTime.UtcNow.AddDays(3).Ticks.ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Name, user.UserName));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, GenerateTotalSeconds().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, GenerateTotalSeconds().ToString()));

            foreach (string role in roles)
                claims.Add(new Claim("role", role));
        }

        private async Task<string> GenerateJwt(ClaimsIdentity claimsIdentity)
        {
            var key = await _jwtService.GetCurrentSigningCredentials();
            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateJwtSecurityToken(new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddHours(_tokenAppSettings.ExpiresIn),
                Issuer = _tokenAppSettings.Issuer,
                Audience = string.Join(", ", _tokenAppSettings.Audiences), 
                Subject = claimsIdentity,
                SigningCredentials = key
            });

            string jwt = tokenHandler.WriteToken(token);
            return jwt;
        }

        private long GenerateTotalSeconds()
        {
            return DateTime.UtcNow.Subtract(new TimeSpan(DateTimeOffset.UnixEpoch.Ticks)).Ticks;
        }

        private async Task<Guid> GenerateRefreshToken(string email)
        {
            RefreshToken refreshToken = new RefreshToken
            {
                UserEmail = email,
                ExpirationDate = DateTime.UtcNow
            };

            _refreshTokenRepository.RemoveRefreshToken(email);
            await _refreshTokenRepository.CreateRefreshToken(refreshToken);

            if (await _refreshTokenRepository.SaveRefreshTokenChanges())
                return await Task.FromResult(refreshToken.Token);
            throw new InvalidOperationException("Não foi possível gerar um refresh token.");
        }
    }
}
