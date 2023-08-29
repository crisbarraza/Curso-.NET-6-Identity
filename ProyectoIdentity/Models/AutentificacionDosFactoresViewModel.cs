using System.ComponentModel.DataAnnotations;

namespace ProyectoIdentity.Models
{
    public class AutentificacionDosFactoresViewModel
    {
        //para acceso
        [Required]
        [Display (Name ="Codigo del autentificador")]
        public string Code { get; set; }

        //para registro
        public string Token;

    }
}
