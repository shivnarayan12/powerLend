const mongoose = require("mongoose");

const paymentSchema =new mongoose.Schema({
    orderDate:{type:Date,default:Date.now},
    payStatus:{type:String}
},{strict:false})




 const PaymentModel=mongoose.model("Payment",paymentSchema);
module.exports =  PaymentModel;