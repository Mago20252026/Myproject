using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class RemoveUserFromTenantRequest
    {
        public Guid UserId { get; set; }
        public Guid TenantId { get; set; }
    }
}
