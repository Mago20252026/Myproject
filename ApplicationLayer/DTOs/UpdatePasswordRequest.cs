using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class UpdatePasswordRequest
    {
        public Guid UserId { get; set; }
        public string NewPassword { get; set; }
    }
}