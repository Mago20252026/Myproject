using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharedDomain.Common;

namespace Domain.Entities
{
    public class UserRole : BaseEntity
    {
        public Guid UserId { get; private set; }
        public Guid RoleId { get; private set; }
        public Guid TenantId { get; private set; }

        public User User { get; private set; }
        public Role Role { get; private set; }
        public Tenant Tenant { get; private set; }


        public UserRole(Guid userId, Guid roleId, Guid tenantId)
        {
            UserId = userId;
            RoleId = roleId;
            TenantId = tenantId;
        }
    }
}