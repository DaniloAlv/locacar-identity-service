using LocacaoDeCarros.Identity.API.Domain;
using LocacaoDeCarros.Identity.API.Models;
using Microsoft.AspNetCore.Identity;

namespace LocacaoDeCarros.Identity.API.Services
{
    public interface IIdentityService
    {
        Task Register(UserRegister userRegister);
        Task<LoginResponse> Login(UserLogin userLogin);
        Task Logout();
        Task ResetPassword(User user, string token, string newPassword);
        Task<string> GenerateResetPasswordToken(User user);
        Task<User> GetUserByEmail(string email);
        Task<User> GetUserById(string id);
    }

    public class IdentityService : IIdentityService
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;

        public IdentityService(UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public async Task<string> GenerateResetPasswordToken(User user)
        {
            var result = await _userManager.GeneratePasswordResetTokenAsync(user);
            return result;
        }

        public async Task<LoginResponse> Login(UserLogin userLogin)
        {
            var result = await _signInManager.PasswordSignInAsync(userLogin.Email, userLogin.Password,
                false, true);

            if (!result.Succeeded)
                throw new InvalidOperationException("Não foi possível realizar o login.");

            if (result.IsLockedOut)
                throw new UnauthorizedAccessException("Seu usuário ainda está bloqueado por excesso de tentativas de login. Tente novamente mais tarde.");

            return new LoginResponse
            {
                
            };
        }

        public async Task Logout()
        {
            await _signInManager.SignOutAsync();
        }

        public async Task Register(UserRegister userRegister)
        {
            var newUser = new User
            {
                Email = userRegister.Email,
                Name = userRegister.Nome
            };

            var result = await _userManager.CreateAsync(newUser, userRegister.Senha);

            if (!result.Succeeded)
                throw new InvalidOperationException("Falha ao registrar o usuário! Tente novamente mais tarde.");


        }

        public async Task ResetPassword(User user, string token, string newPassword)
        {
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

            if (result.Succeeded)
                await Task.CompletedTask;

            throw new InvalidOperationException("Não foi possível atualizar sua senha! Tente novamente mais tarde.");
        }

        public async Task<User> GetUserByEmail(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user is null)
                throw new InvalidOperationException("Não foi encontrado nenhum usuário cadastrado com esse email.");

            return user;
        }

        public async Task<User> GetUserById(string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user is null) throw new InvalidOperationException("Nenhum usuário foi encontrado!");

            return user;
        }
    }
}
