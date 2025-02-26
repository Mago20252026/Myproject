using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.DomainEvents
{
    public class TenantCreatedEvent
    {
        public Guid TenantId { get; private set;}
        public string TenantName {  get; private set;}

        public TenantCreatedEvent(Guid tenantId, string tenantName)
        {
            TenantId=tenantId;
            TenantName=tenantName;
        }
    }
}
