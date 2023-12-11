using LocacaoDeCarros.Identity.API.Models;
using LocacaoDeCarros.Identity.API.Services;
using Microsoft.AspNetCore.Mvc;

namespace LocacaoDeCarros.Identity.API.Controllers
{
    [ApiController]
    [Route("api/autentication")]
    public class IdentityController : ControllerBase
    {
        private readonly IIdentityService _identityService;

        public IdentityController(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> CreateUser([FromBody] UserRegister userRegister)
        {
            try
            {
                var result = await _identityService.Register(userRegister);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest();
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromForm] UserLogin userLogin)
        {
            try
            {
                var loginResponse = await _identityService.Login(userLogin);
                return Ok(loginResponse);
            }
            catch (Exception ex)
            {
                return BadRequest();
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromForm] string email)
        {
            try
            {
                var user = await _identityService.GetUserByEmail(email);
                string passwordResetToken = await _identityService.GenerateResetPasswordToken(user);

                //Enviar por email o link com o id e token
                return Ok(passwordResetToken);
            }
            catch (Exception ex)
            {
                return BadRequest();
            }
        }

        [HttpPost("reset-password/{userId}/{resetToken}")]
        public async Task<IActionResult> ResetPassword([FromRoute] string userId, 
                                                       [FromRoute] string resetToken,
                                                       [FromBody] string newPassword)
        {
            try
            {
                var user = await _identityService.GetUserById(userId);
                await _identityService.ResetPassword(user, resetToken, newPassword);

                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest();
            }
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> GetRefreshToken([FromBody] Guid token)
        {
            try
            {
                var refreshToken = await _identityService.GetRefreshToken(token);

                if (refreshToken is null)
                    return BadRequest("Refresh Token inexistente ou não válido.");

                var userResponse = await _identityService.GetUserResponse(refreshToken.UserEmail);
                return Ok(userResponse);
            }
            catch (Exception ex)
            {
                return BadRequest();
            }
        }

        [HttpGet("logout")]
        public async Task Logout()
        {
            await _identityService.Logout();
        }
    }
}
