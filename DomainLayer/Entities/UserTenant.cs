using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharedDomain.Common;

namespace Domain.Entities
{
    public class UserTenant : BaseEntity
    {


        public Guid UserId { get; private set; }
        public Guid TenantId { get; private set; }

        public User User { get; private set; }
        public Tenant Tenant { get; private set; }
        public TenantRole Role { get; private set; }


        public UserTenant(User user, Tenant tenant, TenantRole role)
        {
            User = user;
            Tenant = tenant;
            Role = role;
            UserId = user.Id;
            TenantId = tenant.Id;
        }
    }
}
