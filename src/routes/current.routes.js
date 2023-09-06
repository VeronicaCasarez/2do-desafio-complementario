import { Router } from "express";
import { __dirname } from "../utils.js";
import { passportCall,authorization} from "../utils.js";
//import { checkRole } from "./middlewares.routes.js";


const router =Router()

router.get('/', passportCall("jwt"), authorization("user") ,(req, res) => {
      res.send(req.user)
    });

  

export default router;

  