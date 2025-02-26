using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class UpdateUserProfileRequest
    {
        public Guid UserId { get; set; }
        public string NewEmail { get; set; }
        public string NewUsername { get; set; }
    }
}