import { Router } from "express";

import Carts from "../dao/dbManagers/cartManager.js";
import productsModel from "../dao/models/product.model.js";
import Product from '../dao/dbManagers/productManager.js'; 

const router = Router();
const cartsManager = new Carts();

const productsManager = new Product();


// Mostrar el carrito
router.get('/', async (req, res) => {
  try {
    const showCart = await cartsManager.getAll();
    res.render('cart',{carts:showCart});
  } catch (error) {
    res.status(500).json({
        message:"Error al mostrar el carrito",
        error:error
    });
  }
});



// Mostrar un carrito por su ID
router.get('/:cartId', async (req, res) => {
  const { cartId } = req.params;
  try {
     const cartData = await cartsManager.getById(cartId);

    if (!cartData) {
      res.status(404).json({ error: "Carrito no encontrado" });
      return;
    }
  
    res.render('cart', { carts: [cartData] }); 
  } catch (error) {
    res.status(500).json({
      message: "Error al obtener el carrito",
      error: error,
    });
  }
});
  
  
    
  // Crear un nuevo carrito
  router.post('/', async (req, res) => {
    const cartData = req.params;
    try {
      const newCart = await cartsManager.save(cartData);
  
      res.json({message:"Carrito creado",data:newCart});
    } catch (error) {
        res.status(500).json({
            message:"Error al crear el carrito",
            error:error
        });
    }
  });
  
//agregar producto al carrito, si ya existe lo incrementa quantity en 1, sino lo agrega
  router.post("/:cid/product/:pid", async (req, res) => {
    try {
      const cartId = req.params.cid;
      const productId = req.params.pid;
  
      const cartData = await cartsManager.getById(cartId);
      if (!cartData) {
        res.status(404).json({ error: "Carrito no encontrado" });
        return;
      }
  
      const existingProduct = await cartsManager.isProductInCart(cartId,productId);
      if (existingProduct) {
        // incrementar la cantidad
        await cartsManager.incrementProductQuantity(cartId, productId);
      } else {
        //  agregar el producto con cantidad 1
        await cartsManager.addProductToCart(cartId, productId);
      }
  
      res.json({
        message: "Operación realizada correctamente",
      });
    } catch (error) {
      res.status(500).json({
        message: "Error en la operación",
        error: error,
      });
    }
  });
  
  
  //eliminar un producto del carrito
 router.delete('/:cartId/:productId', (req, res) => {
    const cartId = req.params.cartId;
    const productId = req.params.productId;
  
    try {
       const success = cartsManager.removeFromCart(cartId, productId);
  
      if (success) {
        res.status(200).json({ message: 'Producto eliminado del carrito' });
      } else {
        res.status(404).json({ message: 'Producto no encontrado' });
      }
    } catch (err) {
      res.status(500).json({ message: 'Error al eliminar un producto del carrito', error: err });
    }
  });
  

//  agregar un arreglo de productos al carrito
router.put('/:cid/', async (req, res) => {
  const cartId = req.params.cid;
  const productsToAdd = req.body.products; 
   try {
    const cart = await cartsManager.getById(cartId);

    if (!cart) {
      return res.status(404).json({ message: 'Carito no encontrado' });
    }
    cart.products = cart.products.concat(productsToAdd);
    await cart.save();

    res.status(200).json({ message: 'Productos agregados al carrito', cart: cart });
  } catch (error) {
    res.status(500).json({ message: 'Error al agregar productos al carrito', error: error });
  }
});


//eliminar todos los productos del carrito
router.delete('/:cid/', async (req, res) => {
  const cartId = req.params.cid;
  try {
    const cart = await cartsManager.getById(cartId);
    if (!cart) {
      return res.status(404).json({ message: 'Carrito no encontrado' });

    }
    cart.products = [];
    await cart.save();

    res.status(200).json({ message: 'Todos los productos del carrito fueron eliminados', cart: cart });
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar todos los productos del carrito', error: error });
  }
});

 //actualizar solo la cantidad de un producto en el carrito
 router.put('/:cid/updatequantity/:productId', async (req, res) => {
  const cartId = req.params.cid;
  const productId = req.params.productId;
  const newQuantity = req.body.quantity; // Nueva cantidad de ejemplares

  try {
    const cart = await cartsManager.getById(cartId);
    if (!cart) {
      return res.status(404).json({ message: 'Cart not found' });
    }
     // Buscar el producto en el carrito por su ID y lo actualiza
    const productToUpdate = await cartsManager.findProductInCartAndUpdateQuantity(cartId, productId, newQuantity);
     // Guardar los cambios en la base de datos
    await cart.save();

    res.status(200).json({ message: 'Cantidad actualizada', cart: cart });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar la cantidad', error: error });
  }
});

  
  // Eliminar el carrito
  // router.delete('/removecart/:cartId', async (req, res) => {
  //   const { cartId } = req.params;
  //   try {
  //     const cartDeleted= await cartsManager.delete(cartId);
  //     res.json({message:"Carrito eliminado",data:cartDeleted});
  //   } catch (error) {
  //       res.status(500).json({
  //           message:"Error al eliminar el carrito",
  //           error:error
  //       });
  //   }
  // });
  
  export default router;