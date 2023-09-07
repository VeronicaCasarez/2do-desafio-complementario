import express from "express";
import handlebars from "express-handlebars";
import MongoStore from "connect-mongo";
import session from "express-session";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import LoginRoute from "./routes/login.routes.js";
import SignupRoute from "./routes/signup.routes.js";
import SessionRoute from "./routes/session.routes.js";
import ProductRouter from "./routes/product.routes.js";
import LogoutRouter from "./routes/logout.routes.js";
import CurrentRouter from "./routes/current.routes.js";
import ForgotRoute from "./routes/forgot.routes.js"
import FailLogin from "./routes/session.routes.js";
import FailRegister from "./routes/session.routes.js";
import passport from "passport";
import initializePassport from "./config/passport.config.js";
import {
  generateToken,
  authToken,
  passportCall,
  authorization,
} from "./utils.js";


import * as dotenv from "dotenv";

import {__dirname} from "./utils.js";

dotenv.config();
const app = express();
app.use(cookieParser("C0d3rS3cr3t"));

const MONGO_URL = process.env.MONGO_URL;
const PORT = process.env.PORT || 8080;

//manejo de archivos staticos y json
app.use(express.static("public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//configuracion de handlebars
app.engine("handlebars", handlebars.engine());
app.set("views", __dirname + "/views");
app.set("view engine", "handlebars");

//manejo de sesion storage
app.use(
  session({
    store: MongoStore.create({
      mongoUrl: MONGO_URL,
      mongoOptions: {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      },
      ttl: 10,
    }),
    secret: "codersecret",
    resave: false,
    saveUninitialized: false,
  })
);

//inicializar passport
initializePassport();
app.use(passport.initialize());
app.use(passport.session()) 

//configuracion de mongoose
const environment = async () => {
  try {
    await mongoose.connect(MONGO_URL);
    console.log("Base de datos conectada");
  } catch (error) {
    console.log(error);
  }
};

environment();



//manejo de las rutas
app.use("/", LoginRoute);
app.use("/signup", SignupRoute);
app.use("/api/session/", SessionRoute);
app.use("/api/products",ProductRouter)
app.use("/logout",LogoutRouter);
app.use("/current",CurrentRouter);
app.use("/forgot", ForgotRoute);
app.use("/",FailLogin)
app.use("/",FailRegister)


const server = app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}!`);
});

server.on("error", (err) => {
  console.error(err);
});