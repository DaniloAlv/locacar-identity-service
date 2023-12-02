using LocacaoDeCarros.Identity.API.Domain;
using LocacaoDeCarros.Identity.API.Services;
using Microsoft.AspNetCore.Identity;
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
        public async Task<IActionResult> CreateUser()
        {
            try
            {

                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest();
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login()
        {
            try
            {
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest();
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            try
            {
                var user = await _identityService.GetUserByEmail(email);
                string passwordResetToken = await _identityService.GenerateResetPasswordToken(user);

                //Enviar por email o link com o id e token
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest();
            }
        }

        [HttpPost("reset-password/{userId:string}/{resetToken:string}")]
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

        [HttpGet("logout")]
        public async Task Logout()
        {
            await _identityService.Logout();
        }
    }
}
