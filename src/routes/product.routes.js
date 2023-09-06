import { Router } from "express";
import mongoose from "mongoose";
import { __dirname } from "../utils.js";
import * as dotenv from "dotenv";
import ProductModel from "../models/product.model.js"; 
import UserModel from "../models/user.model.js"
import { isLoggedIn } from "./middlewares.routes.js";
import productsModel from "../models/product.model.js";

const router = Router();


//NUEVO METODO GET
router.get("/",  async (req, res) => {
  const { limit, page, filter, sort, category, availability } = req.query;
  const defaultLimit = 10;
  const defaultPage = 1;
  
  // Parsea el valor de la página a un número entero
  const currentPage = parseInt(page, 10) || defaultPage;
  
  try {
    let response = await ProductModel.find().lean(); 
    let user= req.session.user;  
    
     // Resolución de los filtros por categoría y disponibilidad
    // if (filter === "category") {
    //   response = await products.getByCategory(category);
    // } else if (filter === "availability") {
    //   response = await products.getByAvailability(availability);
      
    //   }
          
    // // Resolución de la ordenación
    // if (sort === 'asc' || sort === 'desc') {
    //   response.sort((a, b) => {
    //     return sort === 'asc' ? a.price - b.price : b.price - a.price;
    //   });
    // }

 

    const startIndex = (currentPage - 1) * (limit ? +limit : defaultLimit);
    const endIndex = startIndex + (limit ? +limit : defaultLimit);
  
    const paginatedResponse = response.slice(startIndex, endIndex);

    const totalPages = Math.ceil(response.length / (limit ? +limit : defaultLimit));
 
    res.render('product', {
      products: paginatedResponse,
      user:user,
      pagination: {
        status: 'success',
        totalPages: totalPages,
        prevPage: currentPage > 1 ? currentPage - 1 : null,
        nextPage: endIndex < response.length ? currentPage + 1 : null,
        page: currentPage,
        hasPrevPage: currentPage > 1,
        hasNextPage: endIndex < response.length,
        prevLink: currentPage > 1 ? `/api/products?page=${currentPage - 1}` : null,
        nextLink: endIndex < response.length ? `/api/products?page=${currentPage + 1}` : null
      }
    });

  } catch (err) {
    res.status(500).json({
      message: "Error al obtener los productos",
      error: err
    });
  }
});

export default router;
