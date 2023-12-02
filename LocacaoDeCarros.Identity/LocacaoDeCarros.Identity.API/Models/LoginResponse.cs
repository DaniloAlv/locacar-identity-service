namespace LocacaoDeCarros.Identity.API.Models
{
    public class LoginResponse
    {
        public string AccessToken { private get; set; }
        public double ExpiresIn { private get; set; }
        public IEnumerable<UserClaim> Claims { private get; set; }
        public Guid RefreshToken { private get; set; }
    }
}
