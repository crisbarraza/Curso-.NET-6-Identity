using System.ComponentModel.DataAnnotations;

namespace ProyectoIdentity.Models
{
    public class VerificarAutentificadorViewModel
    {
        [Required]
        [Display(Name = "Codigo del autentificador")]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }

        [Display(Name ="Recordar datos?")]
        public bool RecordarDatos { get; set; }

    }
}
