using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System.Net.Mail;
using System.Net;

namespace GG.Web
{
    public class EmailService : IIdentityMessageService
    {
        private string _companyName { get; set; }

        public EmailService()
        {
        }
        public EmailService(string companyName)
        {
            if (string.IsNullOrEmpty(companyName)) throw new NullReferenceException("Company Name Required");
            _companyName = companyName;
        }
        public async Task SendAsync(IdentityMessage message)
        {
            // workaround: just to avoid warning message related to async method
            await SendAsync(message, "");
        }
        public async Task SendAsync(IdentityMessage message, string ccMailAddress)
        {
            if (string.IsNullOrEmpty(_companyName)) throw new NullReferenceException("Company Name Required");

            var MailFrom = "from@mail.t";
            var Host = "mail.google.com";
            var Port = 25;

            Task tsk = new Task(async () =>
            {
                try
                {

                    var fromMail = new MailAddress(MailFrom);
                    var toMail = new MailAddress(message.Destination.Trim());

                    var email = new MailMessage(fromMail, toMail)
                    {
                        Subject = message.Subject,
                        Body = message.Body,
                        IsBodyHtml = true,
                    };
                    if (!string.IsNullOrEmpty(ccMailAddress))
                    {
                        email.CC.Add(ccMailAddress);
                    }

                    using (var client = new SmtpClient(Host, Port)//("192.168.0.101", 259) // for internet
                    {
                        EnableSsl = false, // config.SmtpSettings.EnableSsl,
                        UseDefaultCredentials = false, // for intranet (port: 25)
                    })
                    {
                        if (config.SmtpSettings.AuthRequiried)
                        {
                            client.UseDefaultCredentials = false;
                            NetworkCredential nc = new NetworkCredential();
                            nc.UserName = config.SmtpSettings.Login;
                            nc.Password = config.SmtpSettings.Password;
                            client.Credentials = nc;
                        }
                        else
                        {
                            client.UseDefaultCredentials = true;
                        }
                        await client.SendMailAsync(email);
                    }
                }
                catch (Exception e)
                {
                }
            });
            tsk.Start();
            // workaround: just to avoid warning message related to async method
            await Task.Run(() => { return; });

        }
    }

    //public class SmsService : IIdentityMessageService
    //{
    //    public Task SendAsync(IdentityMessage message)
    //    {
    //        // Plug in your SMS service here to send a text message.
    //        return Task.FromResult(0);
    //    }
    //}

    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.
    public class ApplicationUserManager : UserManager<IdentityUser>
    {
        public ApplicationUserManager(IUserStore<IdentityUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            var manager = new ApplicationUserManager(new UserStore<IdentityUser>(context.Get<SageConnection>() as SageConnection)); //??

            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<IdentityUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 3,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            //// Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            //// You can write your own provider and plug it in here.
            //manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser>
            //{
            //    MessageFormat = "Your security code is {0}"
            //});
            //manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser>
            //{
            //    Subject = "Security Code",
            //    BodyFormat = "Your security code is {0}"
            //});

            manager.EmailService = new EmailService();
            //manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<IdentityUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }

        public override Task<bool> CheckPasswordAsync(IdentityUser user, string password)
        {
            var encode = ServiceLocator.Container.Resolve(typeof(IEncoder), "") as IEncoder;
            var encPass = encode.EncryptDb(password);

            return Task.FromResult(user.PasswordHash == encPass);
            //return base.CheckPasswordAsync(user, password);
        }

        public override Task<IdentityUser> FindByIdAsync(string userId)
        {
            return Store.FindByIdAsync(userId);
            //return base.FindByIdAsync(userId);
        }
    }

    // Configure the application sign-in manager which is used in this application.
    public class ApplicationSignInManager : SignInManager<IdentityUser, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        //??
        public override Task<ClaimsIdentity> CreateUserIdentityAsync(IdentityUser user)
        {
            return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        }

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
}
