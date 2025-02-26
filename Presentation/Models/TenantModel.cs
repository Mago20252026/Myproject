namespace Presentation.Models
{
    public class TenantModel
    {
        public string TenantId { get; set; }
        public string TenantName { get; set; }
        public List<UserModel> Users { get; set; }
    }
}
