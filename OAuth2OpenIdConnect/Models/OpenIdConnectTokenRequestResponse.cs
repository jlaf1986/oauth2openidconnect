﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2OpenIdConnect.Models
{
    public class OpenIdConnectTokenRequestResponse
    {
        [DataMember(Name = "access_token")]
        public string access_token { get; set; }

        [DataMember(Name = "token_type")]
        public string token_type { get; set; }

        [DataMember(Name = "expires_in")]
        public string expires_in { get; set; }

        [DataMember(Name = "refresh_token")]
        public string refresh_token { get; set; }

        [DataMember(Name = "id_token")]
        public string id_token { get; set; }
    }
}
