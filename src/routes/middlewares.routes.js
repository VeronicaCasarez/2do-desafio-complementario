// Middleware para verificar si el usuario está logueado
export function isLoggedIn(req, res, next) {
    if (req.session.user) {
      // Si el usuario está logueado, permite el acceso a la siguiente ruta
      return next();
    } else {
      // Si el usuario no está logueado, redirige al inicio de sesión
      return res.redirect("/");
    }
  }
  

  

  // Middleware para verificar si el usuario tiene autorizacion para ir a la ruta privada
  export function auth(req, res, next) {
    console.log("sesion",req.session);
    if (req.session?.user && req.session?.user.admin) {
       return next();
    }else return res.status(401).json("error de autenticacion");
}

// Middleware para verificar roles
// export function checkRole(req,res,next) {
     
//     if (req.session?.user.role === "administrador") {
//       next(); // Permitir acceso
//     } else {
//       res.status(403).send('Acceso denegado'); // Denegar acceso
//     }
//   };
