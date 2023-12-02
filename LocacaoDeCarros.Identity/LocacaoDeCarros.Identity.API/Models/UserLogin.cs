using System.ComponentModel.DataAnnotations;

namespace LocacaoDeCarros.Identity.API.Models
{
    public class UserLogin
    {
        [Required(ErrorMessage = "O campo {0} deve ser preenchido")]
        [EmailAddress(ErrorMessage = "E-mail informado em valor inválido!")]
        public string Email { get; set; }

        [Required(ErrorMessage = "O campo {0} deve ser preenchido")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
