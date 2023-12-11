namespace LocacaoDeCarros.Identity.API.Models
{
    public class TokenAppSettings
    {
        public int ExpiresIn { get; set; }
        public IEnumerable<string> Audiences { get; set; }
        public string Issuer { get; set; } 
    }
}
