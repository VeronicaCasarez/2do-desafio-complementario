import { Router } from "express";


const router = Router();

// Ruta para cerrar sesión
router.get("", (req, res) => {
    req.session.destroy(err => {
      if (err) {
        console.error("Error al cerrar sesión:", err);
        return res.status(500).json({ respuesta: "Error en el servidor" });
      }
      else{
        console.log("sesion cerrada");
        res.redirect("/"); 
      }
    
    });
  });

  export default router;