using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAppYT.Controllers
{
    [Authorize(Roles = "Admin")]
    [ApiController]
    public class ItemsController : Controller
    {
        public List<string> colorList = new List<string>() { "blue", "red", "green", "yellow", "pink" };

        [HttpGet("GetColorList")]
        public List<string> GetColorList()
        {
            try
            {
                return colorList;
            }
            catch (Exception ex)
            {
                throw;
            }
        }
    }
}
