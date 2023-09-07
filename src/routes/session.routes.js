import { Router } from "express";
import UserModel from "../dao/models/user.model.js";
import notifier from 'node-notifier';
import { passportCall,createHash ,authorization,generateToken, isValidPassword} from "../utils.js";
import passport from "passport";


const router = Router();
//Login con jwt   
router.post("/login", async (req, res) => {
  const { username, password } = req.body
  const user = await UserModel.findOne({ email: username })
  console.log("usuario",user)
  if (!user) {
      return res.json({ status: "error", message: "User not found" })
  } else {
          const myToken = generateToken(user)
          res
          .cookie("CoderKeyQueNadieDebeSaber", myToken, {
              maxAge: 60 * 60 * 1000,
              httpOnly: true
          })
          .json({ status: "success" , respuesta: "Autenticado exitosamente" })
      }
  }
)


// router.get("/current", passportCall("jwt"), authorization("user"), (req, res) => {
//   res.send(req.user)
// })

// router.post("/login", async (req, res) => {
//   const { username, password } = req.body;
//   if (!username || !password) {
//     res.status(400).json({
//       message: "error",
//       data: "Faltan campos",
//     });
//   }
//   let result = await UserModel.find({
//     email: username,
//   });
//   //console.log("aaaaaaaaa", result);
//   if (result) {
//     const role = "admin";
//     const myToken = generateToken({ username, password, role });
//     /* res.status(200).json({
//         message: "success",
//         token: myToken,
//       });
//        } else {
//       res.status(400).json({
//         message: "error",
//         data: "Credenciales invalidas",
//       });
//     }*/
//     res
//       .cookie("CoderKeyQueNadieDebeSaber", myToken, {
//         maxAge: 60 * 60 * 1000,
//       })
//       // .send({ response: "Loggeg in!" })
//       .json({ status: "success" , respuesta: "Autenticado exitosamente" })
//   } else {
//     res.status(401).json({
//       message: "error",
//       data: "Usuario o contraseña incorrectos",
//     });
//   }
// });


//ruta para el login usando passport y faillogin
router.post(
  "/login",
  passport.authenticate("login", {
    failureRedirect: "/failLogin",
  }),
  async (req, res) => {
    if (!req.user) {
      return res.status(401).json("error de autenticacion");
    }
    
    req.session.user = {
      first_name: req.user.first_name,
      last_name: req.user.last_name,
      email: req.user.email,
      age: req.user.age,
    };
    // req.session.admin = true;
    res.status(200).json({ respuesta: "Autenticado exitosamente" });
  // res.send({ status: "success", mesage: "user logged", user: req.user });
  }
);

router.get("/failLogin", async (req, res) => {
  console.log("failed strategy");
  res.send({ error: "failed" });
});


//ruta del login sin passport
// router.post("/login", async (req, res) => {
//   const { username, password } = req.body;
//   const user = await UserModel.findOne({ email: username }).lean();

//   if (!user) {
//     notifier.notify({
//       title: 'Info',
//       message: 'Error en la autenticación.'
//     });

//     return res.status(401).json({ respuesta: "Error de autenticación" });
//   }

//   if (username === 'adminCoder@coder.com' &&  isValidPassword( user.password,password)) {
//     req.session.user = {
//       email: username,
//       admin: true,
//     };

//     notifier.notify({
//       title: 'Info',
//       message: 'Autenticación del administrador.',
//     });
//   } else if ( isValidPassword(user.password,password)) {
//     req.session.user = {
//       email: username,
//       admin: false,
//     };
//   } else {
//     notifier.notify({
//       title: 'Info',
//       message: 'Error en la autenticación.'
//     });

//     return res.status(401).json({ respuesta: "Error de autenticación" });
//   }

//   res.status(200).json({ respuesta: "Autenticado exitosamente" });
// });

//ruta para cambiar contraseña
router.post("/forgot", async (req, res) => {
  const { username, newPassword } = req.body;

  const result = await UserModel.find({
    email: username,
  });
  if (result.length === 0)
    return res.status(401).json({
      respuesta: "el usuario no existe",
    });
  else {
    const respuesta = await UserModel.findByIdAndUpdate(result[0]._id, {
      password: createHash(newPassword),
    });
    console.log(respuesta);
    res.status(200).json({
      respuesta: "se cambio la contrasena",
      datos: respuesta,
    });
  }
});

//ruta para registrarse y para failregister usando passport
router.post(
  "/signup",
  passport.authenticate("register", {
    failureRedirect: "/failRegister",
  }),
  async (req, res) => {
    res.status(200).json({ respuesta: "ok" });
  }
);

router.get("/failRegister", async (req, res) => {
  console.log("failed strategy");
  res.send({ error: "failed" });
});


//ruta para registrarse sin passport
// router.post("/signup", async (req, res) => {
//   const { first_name, last_name, age, email, password } = req.body;

//   const result = await UserModel.create({//crea el usuario
//     first_name,
//     last_name,
//     age,
//     email,
//     password: createHash(password),
//   });

//   if (result === null) {
//     return res.status(401).json({
//       respuesta: "error",
//     });
//   } else {
//     req.session.user = email;
//     req.session.admin = true;
//     res.status(200).json({
//       respuesta: "ok",
//     });
//   }
// });

//ruta para registare con github
router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] }),
  async (req, res) => {}
);

router.get(
  "/githubcallback",
  passport.authenticate("github", { failureRedirect: "/" }),
  async (req, res) => {
    req.session.user = req.user;
    req.session.admin = true;
    res.redirect("/api/products");
  }
);
export default router;
