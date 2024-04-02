using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using User.Management.Service.Models;

namespace User.Management.Service.Service
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
