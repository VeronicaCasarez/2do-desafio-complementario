import { Router } from "express";
import { __dirname } from "../utils.js";
import { passportCall,authorization} from "../utils.js";
import passport from "passport";



const router =Router()
// Ruta para obtener el usuario actual

router.get('/', passportCall('jwt'), (req, res) => {
  // El usuario actual se encuentra en req.user gracias a la estrategia 'jwt'
  if (!req.user) {
    return res.status(401).json({ message: 'Usuario no encontrado' });
  }

  // Renderiza la vista 'current' y pasa los datos del usuario como contexto
  //res.render('current', { user: req.user });
 res.json({ user: req.user });
});

export default router;

  