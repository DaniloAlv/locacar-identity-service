namespace LocacaoDeCarros.Identity.API.Models
{
    public class UserResponse
    {
        public string AccessToken { get; set; }
        public double ExpiresIn { get; set; }
        public Guid RefreshToken { get; set; }
        public UserToken User { get; set; }

    }

    public class UserToken
    {
       public Guid Id { get; set; }
       public string Email { get; set; }
       public IEnumerable<UserClaim> Claims { get; set; }
    }
}
