using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2OpenIdConnect.Models
{
    [DataContract]
    public class OpenIdConnectGraph
    {
        [DataMember(Name = "sub")]
        public string Id { get; set; }

        [DataMember(Name = "given_name")]
        public string FirstName { get; set; }

        [DataMember(Name = "family_name")]
        public string LastName { get; set; }

        [DataMember(Name = "name")]
        public string FullName { get; set; }

        [DataMember(Name = "email")]
        public string Email { get; set; }

        [DataMember(Name = "profile")]
        public string Profile { get; set; }
    }
}
