using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using ProyectoIdentity.Datos;
using ProyectoIdentity.Servicios;

var builder = WebApplication.CreateBuilder(args);

//Configuramos la conexión a sql server
builder.Services.AddDbContext<ApplicationDbContext>(opciones => 
    opciones.UseSqlServer(builder.Configuration.GetConnectionString("ConexionSql"))
);

//Agregar el servicio Identity a la aplicación
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

//Esta línea es para la url de retorno al acceder
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = new PathString("/Cuentas/Acceso");
    options.AccessDeniedPath = new PathString("/Cuentas/Bloqueado");
});

//Estas son opciones de configuración del identity
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 5;
    options.Password.RequireLowercase = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 3;
});

//Agregar autenticación de facebook
builder.Services.AddAuthentication().AddFacebook(options =>
{
    options.AppId = "297709012325292";
    options.AppSecret = "4e0cbee917d9bae76655314274119297";
});

//Agregar autenticación de google
builder.Services.AddAuthentication().AddGoogle(options =>
{
    options.ClientId = "228603965289-ce9gi69u2pp3m19em861lhjiepfnhav0.apps.googleusercontent.com";
    options.ClientSecret = "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";
});

//Se agregar IEmailSender
builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
//Se agrega la autenticación
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
