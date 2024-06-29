using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ConexionEF.Models
{
    public class UserViewModel
    {
        public UserViewModel()
        {
            
        }
        public string? User { get; set; }

        public string? Email { get; set;}

        public bool Confirmed { get; set; }

        public bool IsAdmin { get; set; }
         public bool IsVendedor { get; set; }

    }
}