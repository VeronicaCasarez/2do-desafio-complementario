import { fileURLToPath } from 'url';
import { dirname } from 'path';
import jwt from "jsonwebtoken";
import passport from "passport";
import bcrypt from 'bcrypt';
export const __filename = fileURLToPath(import.meta.url);
export const __dirname = dirname(__filename);


const PRIVATE_KEY = "CoderKeyQueNadieDebeSaber";

export const generateToken = (user) => {
  const token = jwt.sign({ user }, PRIVATE_KEY, { expiresIn: "1h" });
  return token;
};

export const authToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) res.status(401).json({ error: "Error de autenticacion" });

  const token = authHeader.split(" ")[1];

  jwt.verify(token, PRIVATE_KEY, (err, user) => {
    if (err) res.status(401).json({ error: "Token invalido" });

    req.user = user;
    next();
  });
};

export const passportCall = (strategy) => {
  return async (req, res, next) => {
    passport.authenticate(strategy, (error, user, info) => {
      if (error) {
        return next(error); // Manejar errores de autenticación
      }
      
      if (!user) {
        if (info && info.message) {
          return res.status(401).json({ status: "error", message: info.message });
        } else {
          return res.status(401).json({ status: "error", message: "No autorizado" });
        }
      }

      req.user = user; // Asignar el usuario a req.user
      next();
    })(req, res, next);
  };
};


export const authorization = (role)=>{
    return async(req,res,next)=>{
        if(!req.user) return res.json({status: "error", message: "Unauthorized"})
        if(req.user.user.role !== role) return res.json({status: "error", message: "UnauthorizeD"})
        next()
    }
}

//logica para hashear la contraseña
export const createHash = (password) =>
  bcrypt.hashSync(password, bcrypt.genSaltSync(10));

  //logica para comparar la contraseña sin hashear con la que esta en la base de datos
  //devuelve true o false
export const isValidPassword = (savedPassword, password) => {
  console.log({ "cloud password": savedPassword, loginPassword: password });
  return bcrypt.compareSync(password, savedPassword);
};
