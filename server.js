
const express = require('express');
const mongoose = require('mongoose');
const Razorpay = require('razorpay');
const shortid = require('shortid');
const crypto = require('crypto');
const cors = require('cors');
const UserexpModel = require('./models/userexp.js');
const UserreportModel = require('./models/userreport.js');
const ProductModel = require('./models/products.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const UserModel = require('./models/users.js');
const PaymentModel = require('./models/Payment.js');
require('dotenv').config();
const app = express();

// Increase payload size limit to 50MB (or adjust as needed)
app.use(express.json({ limit: "500mb" }));
app.use(express.urlencoded({ limit: "500mb", extended: true }));



const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET,
});



app.use(cors({
  origin: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

app.use(cookieParser());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Database connection successful"))
  .catch(err => {
    console.error("Database connection error", err);
    process.exit(1); // Exit process if the database connection fails
  });

// JWT Token Verification Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies.tok || req.headers["authorization"];
  if (!token) return res.status(403).json("Access denied");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    console.log(decoded);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json("Invalid Token");
  }
};






// Experience Routes
app.get("/getUserexp", (req, res) => {
  UserexpModel.find()
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.post("/createExperience", (req, res) => {
  UserexpModel.create(req.body)
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.delete("/deleteExp/:id", (req, res) => {
  const id = req.params.id;
  UserexpModel.findByIdAndDelete(id)
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

// Report Routes
app.get("/getUserreport", (req, res) => {
  UserreportModel.find()
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.delete("/deleteReport/:id", (req, res) => {
  const id = req.params.id;
  UserreportModel.findByIdAndDelete(id)
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.post("/createReport", (req, res) => {
  UserreportModel.create(req.body)
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

// Product Routes
app.get("/getProduct", (req, res) => {
  ProductModel.find()
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.post("/createProduct", (req, res) => {
  ProductModel.create(req.body)
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.delete("/deleteProduct/:id", (req, res) => {
  const id = req.params.id;
  ProductModel.findByIdAndDelete(id)
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.put("/updateProduct/:id", (req, res) => {
  const id = req.params.id;
  ProductModel.findByIdAndUpdate(id, req.body, { new: true })
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.get("/getUp/:id", (req, res) => {
  const id = req.params.id;
  ProductModel.findById(id)
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

// Cart Routes
app.post("/createCart/:userid", (req, res) => {
  const id = req.params.userid;
  const cartbody = req.body;
  UserModel.findByIdAndUpdate(id, { $push: { cart: cartbody } })
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.get("/getCart/:userid", (req, res) => {
  const id = req.params.userid;
  UserModel.findById(id)
    .then(e => res.json(e.cart))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.post("/deleteCart/:id", (req, res) => {
  const id = req.params.id;
  const { userid } = req.body;
  UserModel.findByIdAndUpdate(userid, { $pull: { cart: { _id: id } } })
    .then(e => res.json(e))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

// User Authentication Routes
app.post("/register", (req, res) => {
  const { username, email, phone, password } = req.body;
  UserModel.findOne({ email })
    .then(existingUser => {
      if (existingUser) return res.status(400).json({ error: "User already exists" });
      bcrypt.hash(password, 10)
        .then(hash => {
          UserModel.create({ username, email, phone, password: hash })
            .then(() => res.json("Success!"))
            .catch(err => res.status(500).json({ error: "Database error", details: err }));
        })
        .catch(err => res.status(500).json({ error: "Hashing failed", details: err }));
    })
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  UserModel.findOne({ email })
    .then(user => {
      if (!user) return res.status(404).json({ error: "User not found" });
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (!isMatch) return res.status(401).json({ error: "Incorrect password" });
        const token = jwt.sign({ email: user.email, role: user.role }, process.env.JWT_SECRET_KEY, { expiresIn: "365d" });
        return res.json({ Status: "success", role: user.role, id: user._id, tok: token });
      });
    })
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

// User Profile Routes
app.get("/getUser/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  UserModel.findById(id)
    .then(user => {
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json(user);
    })
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});



app.get("/getUpUser/:id", verifyToken, (req, res) => {
  const id = req.params.id;

  UserModel.findById(id)
    .then(user => {
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json(user);
    })
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});


app.put("/updateUser/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  // console.log("backend id",id);
  UserModel.findByIdAndUpdate(id, req.body, { new: true })
    .then(user => res.json(user))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});




app.get("/getUserDetails", (req, res) => {
  UserModel.find()
    .then(users => res.json(users))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});

app.delete("/deleteUser/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  UserModel.findByIdAndDelete(id)
    .then(user => res.json(user))
    .catch(err => res.status(500).json({ error: "Database error", details: err }));
});





//-------------------TO UPDATE ORDER COUNT---------------------------



app.put("/update-order-count/:id", async (req, res) => {
  try {
    const id = req.params.id;
    // console.log('UserID1:', id);

    const user = await UserModel.findById(id);


    if (!user) {
      console.log('User not found');
      return res.status(404).json({ success: false, message: "User not found" });
    }
    user.orders += 1;
    await user.save();

    console.log('Order updated successfully:', user.orders);
    res.json({ success: true, orders: user.orders });
  } catch (error) {
    console.error('Error updating order count:', error);
    res.status(500).json({ success: false, message: 'Error updating order count' });
  }
});


//------------------We have to make two route for payment---------


app.post("/create-order", async (req, res) => {
    try {
        const { amount } = req.body; // Receive the amount from the frontend

        // Validate amount
        if (!amount || amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        const options = {
            amount: amount * 100, // Convert to the smallest currency unit (paise for INR)
            currency: 'INR',
            receipt: shortid.generate(), // Optional, for tracking
        };

        const order = await razorpay.orders.create(options);
        res.status(200).json({
            id: order.id,
            currency: order.currency,
            amount: order.amount,
        });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Error creating order', details: error.message });
    }
});


app.post("/verifyPayment", (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

  // Step 1: Create a hash using the Razorpay secret
  const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_SECRET);
  hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
  const generatedSignature = hmac.digest('hex');

  // Step 2: Compare the generated hash with the Razorpay signature
  if (generatedSignature === razorpay_signature) {
      // Signature matches, payment is valid
      return res.status(200).json({ status: 'success', message: 'Payment verified successfully!' });
  } else {
      // Signature mismatch, payment failed
      return res.status(400).json({ status: 'failed', message: 'Payment verification failed!' });
  }
});

// Start the server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
