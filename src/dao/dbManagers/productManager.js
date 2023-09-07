import productsModel from '../models/product.js';
import notifier from 'node-notifier';

export default class Products {
  async getAll() {
    return await productsModel.find({}).lean();
  }

  async getById(id) {
    return await productsModel.findById(id);
  };

 
  async getByCategory(filter) {
    const products = await productsModel.find()
    const productsByCategory = products.filter(
      (p) => String(p.category) == filter
   );
 
   return productsByCategory;
}


async getByAvailability(filter) {
  try {
    const products = await productsModel.find();
    const productsByAvailability = products.filter(
      (p) => String(p.availability) == filter
    );
    if (productsByAvailability.length>0){ 
         return productsByAvailability;
    }else{
      notifier.notify({
        title: 'Info',
        message: 'No existe un producto con esa disponibilidad.'
      });
    }
  } catch (error) {
    console.error("Error al obtener productos por disponibilidad", error);
    throw error;
  }
}


  async save(data) {
    const newProduct = await productsModel.create(data);
    return newProduct;
  };

  async update(id, data) {
    const updatedProduct = await productsModel.findByIdAndUpdate(id, data, { new: true });
    return updatedProduct;
  };

  async delete(id) {
    const deletedProduct = await productsModel.findByIdAndDelete(id);
    return deletedProduct;
  };
}
