using Backend.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Backend.Controllers
{
    [Route("/[controller]")]
    public class IdentityController : ControllerBase
    {
        UserManager<IdentityUser> _userManager;
        SignInManager<IdentityUser> _signInManager;

        public IdentityController(
            UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
        [Route("/[controller]/[action]")]
        public ActionResult<string> Encrypt([FromQuery] string text, string pepper)
        {
            var encrytedText = Encryption.EncryptString(text, pepper);

            return Ok(encrytedText + Environment.NewLine);
        }

        [HttpPost]
        [Route("/[controller]/[action]")]
        public async Task<ActionResult<RegisterResponseModel>> Register([FromBody] UserPasswordModel input)
        {
            var user = new IdentityUser { UserName = input.Email, Email = input.Email };
            var result = await _userManager.CreateAsync(user, input.Password);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return new RegisterResponseModel { HasSucceeded = true, Message = "User created a new account with password." };
            }

            return new RegisterResponseModel { HasSucceeded = false, Message = "oops, something went wrong", IdentityErrors = result.Errors.ToList() };
        }

        [HttpPost]
        [Route("/[controller]/[action]")]
        public ActionResult<LoginResultModel> Login([FromBody] UserPasswordModel input)
        {
            var hashAlgorithm = SHA512.Create();
            var passwordBytes = Encoding.UTF8.GetBytes(input.Password);
            var passwordHash = BitConverter.ToString(hashAlgorithm.ComputeHash(passwordBytes)).Replace("-", "").ToLower();
            
            // checking master password
            if (passwordHash != "c7a0bc7f9bcaee3e3d007b7ddd37d7aa764081a2da6ec704f242ce55183aff826e05ff3a8ef4515aa58d7d55a86c8a866831b1862f6e21d751207b22b4eedded")
            {
                // check fails => login unsuccessful
                var failModel = new LoginResultModel { UserName = input.Email, HasSucceeded = false, Message = "Invalid login attempt." };
                return failModel;
            }

            // successful login
            var successModel = new LoginResultModel { UserName = input.Email, HasSucceeded = true, Message = "You have successfully logged in." };
            return successModel;
        }
    }
}