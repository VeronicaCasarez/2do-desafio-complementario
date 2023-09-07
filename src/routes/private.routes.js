import { Router } from "express";
import { __dirname } from "../utils.js";
import { auth } from "./middlewares.routes.js";
//import { checkRole } from "./middlewares.routes.js";


const router =Router()

router.get('/', auth, (req, res) => {
      res.render('private',{})
    });



export default router;
