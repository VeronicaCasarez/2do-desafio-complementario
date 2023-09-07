import mongoose from 'mongoose';

const cartsCollection = 'Carts';

const cartSchema = mongoose.Schema({
  products: {
    type: [
      {
        product: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Products",
        },
        quantity: {
          type: Number,
        },
      },
    ],
    default: [],
  },
});

cartSchema.pre("findById", function () {
  this.populate("products.product");
});

cartSchema.pre("findOne", function () {
  this.populate("products.product");
});

cartSchema.pre("find", function () {
  this.populate("products.product");
});

const cartModel = mongoose.model(cartsCollection, cartSchema);

export default cartModel;