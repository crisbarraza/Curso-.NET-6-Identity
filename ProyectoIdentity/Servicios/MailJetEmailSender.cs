using Mailjet.Client;
using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Identity.UI.Services;
using Newtonsoft.Json.Linq;

namespace ProyectoIdentity.Servicios
{
    public class MailJetEmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        public OpcionesMailJet _opcionesMailJet;

        public MailJetEmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {

            _opcionesMailJet = _configuration.GetSection("MailJet").Get<OpcionesMailJet>();

            MailjetClient client = new MailjetClient(_opcionesMailJet.ApiKey, _opcionesMailJet.SecretKey)
            {
                Version = ApiVersion.V3_1,
            };
            MailjetRequest request = new MailjetRequest
            {
                Resource = Send.Resource,
            }
             .Property(Send.Messages, new JArray {
     new JObject {
      {
       "From",
       new JObject {
        {"Email", "admin@render2web.com"},
        {"Name", "render2web"}
       }
      }, {
       "To",
       new JArray {
        new JObject {
         {
          "Email",
          email
         }, {
          "Name",
          "José"
         }
        }
       }
      }, {
       "Subject",
       subject
      }, {
       "HTMLPart",
       htmlMessage
      }
     }
             });
            await client.PostAsync(request);
        }
    }
}