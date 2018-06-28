using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using GoCommando;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace JwtCmd.Commands
{
    [Command("validate")]
    public class ValidateCommand : ICommand
    {
        [Parameter("authority", "a", false)]
        public string Authority { get; set; }

        [Parameter("audience", "u", false)]
        public string Audience { get; set; }

        [Parameter("token", "t", false)]
        public string Token { get; set; }

        public void Run()
        {
            try
            {
                Console.WriteLine(string.Empty);

                var manager = new ConfigurationManager<OpenIdConnectConfiguration>($"{Authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());

                var config = manager.GetConfigurationAsync().GetAwaiter().GetResult();

                Console.WriteLine("==================== CONFIGURATION ====================");
                Console.WriteLine(JsonConvert.SerializeObject(config, Formatting.Indented));
                Console.WriteLine(string.Empty);

                SecurityToken securityToken = null;

                var param = new TokenValidationParameters
                {
                    ValidIssuer = Authority,
                    ValidAudiences = new[] { Audience },
                    IssuerSigningKeys = config.SigningKeys,
                    ValidateIssuer = true,
                };

                Console.WriteLine("==================== PARAMETERS ====================");
                Console.WriteLine(JsonConvert.SerializeObject(param, Formatting.Indented));
                Console.WriteLine(string.Empty);

                var handler = new JwtSecurityTokenHandler();

                var user = handler.ValidateToken(Token, param, out securityToken);

                Console.WriteLine("==================== CLAIMS ====================");
                var claims = new Dictionary<string, string>();
                foreach (var i in user.Claims) claims.Add(i.Type, i.Value);
                Console.WriteLine(JsonConvert.SerializeObject(claims, Formatting.Indented));
                Console.WriteLine(string.Empty);
            }
            catch (Exception e)
            {
                Console.WriteLine("==================== ERROR ====================");
                Console.WriteLine(JsonConvert.SerializeObject(e, Formatting.Indented));
                Console.WriteLine(string.Empty);
            }
        }
    }
}