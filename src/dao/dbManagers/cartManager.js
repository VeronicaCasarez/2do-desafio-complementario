import cartModel from "../models/cart.js";


export default class Carts {
  //obtener todos los carritos
  async getAll() {
    return await cartModel.find({}).lean();
  };
 //obtener un carrito
  async getOne (id)  {
    let result = await cartModel.findById(id).lean();
    return result;
  };
  
  //obtener carrito por id
  async getById(id) {
    return await cartModel.findById(id)
  };

  //crear carrito
  async save(data) {
    const newCart = await cartModel.create(data);
    return newCart;
 };

 //actualizar carrito
  async update(id, data) {
    const updatedCart = await  cartModel.findByIdAndUpdate(id, {products:data});
    return updatedCart;
  };

//eliminar carrito
  async delete(id) {
    const deletedCart = await cartModel.findByIdAndDelete(id);
    return deletedCart;
  };

 //Eliminar del carrito el producto seleccionado***
 async removeFromCart(cid, pid) {
  try {
    const cart = await cartModel.findOne({ _id: cid });
    const updatedProducts = cart.products.filter(
      (p) => String(p.product._id) !== pid
    );
    cart.products = updatedProducts;
    const updatedCart = await cart.save();

    if (!updatedCart) {
      console.log("Carrito no encontrado");
      return null;
    }

    console.log("Carrito actualizado", updatedCart);
    return updatedCart;
  } catch (error) {
    console.error("Error al eliminar producto del carrito", error);
    throw error;
  }
}


  //buscar un producto en el carrito
  async  isProductInCart(cartId, productId) {
    try {
      const cart = await cartModel.findOne({ _id: cartId });
      if (cart) {
        const productInCart = cart.products.some(({ product }) => String(product._id) === productId);
        if (productInCart) {
          return productInCart;
        } else {
          return null; // El producto no está en el carrito
        }
      } else {
        return null; // Carrito no encontrado
      }
    } catch (error) {
      console.error("Error al buscar producto en el carrito:", error);
      throw error;
    }
  }
  
  
//incrementar quantity, el producto ya existe en el carrito
   async incrementProductQuantity(cid, pid) {
    try {
      const cart = await cartModel.findOne({ _id: cid });
      const productIndex = cart.products.findIndex(
        (p) => String(p.product._id) === pid
      );
      if (productIndex !== -1) {
        cart.products[productIndex].quantity += 1;
        const updatedCart = await cart.save();
  
        if (!updatedCart) {
          console.log("Carrito no encontrado");
          return null;
        }
  
        console.log("Carrito actualizado", updatedCart);
        return updatedCart;
      } else {
        console.log("Producto no encontrado en el carrito");
        return null;
      }
    } catch (error) {
      console.error("Error al incrementar la cantidad del producto", error);
      throw error;
    }
  }
  
  
// agregar un producto al carrito con cantidad 1**
async addProductToCart(cid, pid) {
  try {
    const cart = await cartModel.findOne({ _id: cid });
    const productExists = cart.products.some(
      (p) => String(p.product) === pid
    );

    if (!productExists) {
      const newProduct = { product: pid, quantity: 1 }; // Agregar cantidad inicial
      cart.products.push(newProduct);
      const updatedCart = await cart.save();

      if (!updatedCart) {
        console.log("Carrito no encontrado");
        return null;
      } 
      console.log("Carrito actualizado", updatedCart);
      return updatedCart;
      
    }
  } catch (error) {
    console.error("Error al agregar producto al carrito", error);
    throw error;
  }
}


   //encontrar un producto en el carrito por id y actualizar la cantidad 
   //en varios
  async findProductInCartAndUpdateQuantity(cid, pid, newQuantity) {
    try {
      const cart = await cartModel.findOne({ _id: cid });
      const productIndex = cart.products.findIndex(
        (p) => String(p.product._id) === pid
      );
      if (productIndex !== -1) {
        cart.products[productIndex].quantity=newQuantity;
        const updatedCart = await cart.save();
  
        if (!updatedCart) {
          console.log("Carrito no encontrado");
          return null;
        }
  
        console.log("Carrito actualizado");
        return updatedCart;
      } else {
        console.log("Producto no encontrado en el carrito");
        return null;
      }
    } catch (error) {
      console.error("Error al incrementar la cantidad del producto", error);
      throw error;
    }
  }
}