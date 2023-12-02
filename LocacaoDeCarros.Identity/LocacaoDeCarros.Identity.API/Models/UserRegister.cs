using System.ComponentModel.DataAnnotations;

namespace LocacaoDeCarros.Identity.API.Models
{
    public class UserRegister
    {
        [Required(ErrorMessage = "O campo {0} precisa ser informado!")]
        [EmailAddress(ErrorMessage = "Email em formato inválido!")]
        public string Email { get; set; }

        [Required(ErrorMessage = "O campo {0} precisa ser informado!")]
        [DataType(DataType.Password)]
        public string Senha { get; set; }

        [Required(ErrorMessage = "O campo {0} precisa ser informado!")]
        [DataType(DataType.Password)]
        [Compare("Senha", ErrorMessage = "As senhas não possuem o mesmo valor!")]
        public string ConfirmacaoSenha { get; set; }

        [Required(ErrorMessage = "O campo {0} precisa ser informado!")]
        public string Nome { get; set; }

        [Required(ErrorMessage = "O campo {0} precisa ser informado!")]
        [MaxLength(11)]
        public string Cpf { get; set; }
    }
}
