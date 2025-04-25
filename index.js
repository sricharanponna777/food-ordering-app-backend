// server.js
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const qrcode = require('qrcode');
const nodemailer = require('nodemailer');
const path = require('path');
const multer = require('multer');
const fs = require('fs')
const axios = require('axios');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ CORS middleware — this handles everything including OPTIONS
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ storage });

// Function to download file from URL
const downloadImageFromURL = async (imageUrl) => {
  const response = await axios({
    url: imageUrl,
    method: 'GET',
    responseType: 'stream',
  });

  const filePath = path.join(__dirname, 'uploads', `${Date.now()}-${path.basename(imageUrl)}`);
  const writer = fs.createWriteStream(filePath);

  // Pipe the response to the file
  response.data.pipe(writer);

  return new Promise((resolve, reject) => {
    writer.on('finish', () => resolve(filePath));
    writer.on('error', reject);
  });
};
// Email configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_SERVICE,
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Access denied' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Role-based access control middleware
const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.user_type)) {
      return res.status(403).json({ message: 'You do not have permission to access this resource' });
    }
    next();
  };
};

app.get('/', (req, res) => {
  return res.send("Hi")
});

app.get('/api/get-user-type', authenticateToken, async (req, res) => {
  try {
    return res.send(req.user.user_type)
  } catch {
    return res.status(403).json({ message: 'Invalid Token' });
  }
})

// Register new user
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, phone, user_type } = req.body;
    
    // Check if user already exists
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    if (user_type !== "customer" && user_type !== "merchant" && user_type !== "agent") {
      return res.status(400).json({ message: 'Please give one of the 3 user types (customer, merchant, agent) and make sure it isn\'t misspelt. This API is also case sensitive so it won\'t allow any uppercase letters' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Insert user
    const newUser = await pool.query(
      'INSERT INTO users (email, password, name, phone, user_type) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [email, hashedPassword, name, phone, user_type]
    );
    
    // Create specific profile based on user type
    if (user_type === 'merchant') {
      const { business_name, description, address, logo_url } = req.body;
      await pool.query(
        'INSERT INTO merchants (user_id, business_name, description, address, logo_url) VALUES ($1, $2, $3, $4, $5)',
        [newUser.rows[0].id, business_name, description, address, logo_url || null]
      );
    } else if (user_type === 'agent') {
      await pool.query('INSERT INTO agents (user_id) VALUES ($1)', [newUser.rows[0].id]);
    }
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Check if user is a merchant
    const isMerchant = user.user_type === 'merchant';

    // Check if user is an agent
    const isAgent = user.user_type === "agent";

    // Check if user is a customer
    const isCustomer = user.user_type === "customer";
    
    // Create token
    const token = jwt.sign(
      { id: user.id, email: user.email, user_type: user.user_type },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Send response with token, user_type, and isMerchant flag
    res.json({ 
      token, 
      user_type: user.user_type, 
      name: user.name,
      isMerchant,
      isAgent,
      isCustomer
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});


// app.post('/refresh-token', async (req, res) => {
//   const { refreshToken } = req.body;

//   if (!refreshToken) {
//     return res.status(400).json({ message: 'Refresh token required' });
//   }

//   try {
//     // Check if refresh token exists in DB and not expired
//     const tokenQuery = await pool.query(
//       'SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()',
//       [refreshToken]
//     );

//     if (tokenQuery.rowCount === 0) {
//       return res.status(403).json({ message: 'Invalid or expired refresh token' });
//     }

//     const tokenRow = tokenQuery.rows[0];

//     // Verify token signature
//     jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, async (err, decoded) => {
//       if (err) {
//         return res.status(403).json({ message: 'Invalid refresh token' });
//       }

//       const userId = decoded.userId;

//       // Rotate: delete old token
//       await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);

//       // Create new tokens
//       const newAccessToken = generateAccessToken(userId);
//       const newRefreshToken = generateRefreshToken(userId);

//       // Save new refresh token
//       const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
//       await pool.query(
//         'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
//         [userId, newRefreshToken, expiresAt]
//       );

//       res.json({
//         accessToken: newAccessToken,
//         refreshToken: newRefreshToken,
//       });
//     });
//   } catch (error) {
//     console.error('Refresh error:', error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// CUSTOMER ROUTES

// Get all merchants
app.get('/api/merchants', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT m.*, u.name as contact_name FROM merchants m JOIN users u ON m.user_id = u.id WHERE m.is_active = true'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching merchants:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/merchants/:id/categories', async (req, res) => {
  const merchantId = req.params.id;

  try {
    const result = await pool.query(
      `
      SELECT DISTINCT c.id, c.name
      FROM categories c
      INNER JOIN products p ON c.id = p.category_id
      WHERE c.merchant_id = $1 AND p.is_available = true
      ORDER BY c.name ASC
      `,
      [merchantId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// Get merchant details with products
app.get('/api/merchants/:id', async (req, res) => {
  try {
    const merchantId = req.params.id;
    
    // Get merchant details
    const merchantResult = await pool.query(
      'SELECT m.*, u.name as contact_name FROM merchants m JOIN users u ON m.user_id = u.id WHERE m.id = $1',
      [merchantId]
    );
    
    if (merchantResult.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant not found' });
    }
    
    // Get categories
    const categoriesResult = await pool.query(
      'SELECT * FROM categories WHERE merchant_id = $1',
      [merchantId]
    );
    
    // Get products
    const productsResult = await pool.query(
      'SELECT * FROM products WHERE merchant_id = $1 AND is_available = true',
      [merchantId]
    );
    
    res.json({
      ...merchantResult.rows[0],
      categories: categoriesResult.rows,
      products: productsResult.rows
    });
  } catch (error) {
    console.error('Error fetching merchant details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all products from a merchant
app.get('/api/merchants/:id/products', async (req, res) => {
  try {
    const merchantId = req.params.id;
    const { category_id, min_price, max_price } = req.query;

    let query = `
      SELECT p.*, c.name as category_name 
      FROM products p 
      LEFT JOIN categories c ON p.category_id = c.id 
      WHERE p.merchant_id = $1 AND p.is_available = true
    `;

    const params = [merchantId];
    let paramIndex = 2;

    // Add category filter
    if (category_id) {
      query += ` AND p.category_id = $${paramIndex++}`;
      params.push(category_id);
    }

    // Add min_price filter
    if (min_price) {
      query += ` AND p.price >= $${paramIndex++}`;
      params.push(min_price);
    }

    // Add max_price filter
    if (max_price) {
      query += ` AND p.price <= $${paramIndex++}`;
      params.push(max_price);
    }

    // Final ordering
    query += ` ORDER BY p.created_at DESC`;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a new order
app.post('/api/orders', authenticateToken, authorize(['customer']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { merchant_id, items, notes } = req.body;
    const customer_id = req.user.id;
    
    await client.query('BEGIN');
    
    // Calculate total amount and verify products
    let total_amount = 0;
    for (const item of items) {
      const productResult = await client.query(
        'SELECT price, is_available FROM products WHERE id = $1 AND merchant_id = $2',
        [item.product_id, merchant_id]
      );
      
      if (productResult.rows.length === 0 || !productResult.rows[0].is_available) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: `Product ${item.product_id} is unavailable` });
      }
      
      const price = parseFloat(productResult.rows[0].price);
      const subtotal = price * item.quantity;
      total_amount += subtotal;
      item.unit_price = price;
      item.subtotal = subtotal;
    }
    
    // Create order
    const orderResult = await client.query(
      'INSERT INTO orders (customer_id, merchant_id, total_amount, notes, status) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [customer_id, merchant_id, total_amount, notes, 'pending']
    );
    
    const order = orderResult.rows[0];
    
    // Create order items
    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal, notes) VALUES ($1, $2, $3, $4, $5, $6)',
        [order.id, item.product_id, item.quantity, item.unit_price, item.subtotal, item.notes]
      );
    }
    
    // Record status history
    await client.query(
      'INSERT INTO order_status_history (order_id, status, changed_by) VALUES ($1, $2, $3)',
      [order.id, 'pending', customer_id]
    );
    
    // Generate QR code for order
    const qrCodeData = JSON.stringify({
      order_id: order.id,
      customer_id,
      merchant_id,
      timestamp: new Date().toISOString()
    });
    
    const qrCodePath = `uploads/qr-${order.id}.png`;
    await qrcode.toFile(path.join(__dirname, qrCodePath), qrCodeData);
    
    // Update order with QR code URL
    const qrCodeUrl = `${process.env.API_URL}/${qrCodePath}`;
    await client.query(
      'UPDATE orders SET qr_code_url = $1 WHERE id = $2',
      [qrCodeUrl, order.id]
    );
    
    // Send email with QR code
    const userResult = await client.query('SELECT email, name FROM users WHERE id = $1', [customer_id]);
    const user = userResult.rows[0];
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: `Your Order Confirmation #${order.id}`,
      html: `
        <h1>Thank you for your order, ${user.name}!</h1>
        <p>Your order #${order.id} has been received and is being processed.</p>
        <p>Show this QR code to the collection agent when collecting your order:</p>
        <img src="cid:qr-code" />
        <p>Order Total: £${parseFloat(total_amount).toFixed(2)}</p>
      `,
      attachments: [{
        filename: 'qr-code.png',
        path: path.join(__dirname, qrCodePath),
        cid: 'qr-code'
      }]
    };
    
    await transporter.sendMail(mailOptions);
    
    // Create Stripe PaymentIntent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: total_amount * 100,  // Convert to pennies
      currency: 'gbp',
      payment_method_types: ['card'],
    });
    
    // Respond with clientSecret and order details
    res.status(201).json({
      order_id: order.id,
      status: order.status,
      total_amount,
      qr_code_url: qrCodeUrl,
      clientSecret: paymentIntent.client_secret,  // Send clientSecret for frontend payment confirmation
    });

    await client.query('COMMIT');
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error creating order:', error);
    res.status(500).json({ message: 'Server error during order creation' });
  } finally {
    client.release();
  }
});


// Get customer orders
app.get('/api/orders/my', authenticateToken, authorize(['customer']), async (req, res) => {
  try {
    const customerId = req.user.id;
    
    const result = await pool.query(
      `SELECT o.*, m.business_name as merchant_name
       FROM orders o
       JOIN merchants m ON o.merchant_id = m.id
       WHERE o.customer_id = $1
       ORDER BY o.created_at DESC`,
      [customerId]
    );
    
    // Get items for each order
    for (let order of result.rows) {
      const itemsResult = await pool.query(
        `SELECT oi.*, p.name as product_name, p.image_url
         FROM order_items oi
         JOIN products p ON oi.product_id = p.id
         WHERE oi.order_id = $1`,
        [order.id]
      );
      order.items = itemsResult.rows;
    }
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching customer orders:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get order details
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const orderId = req.params.id;
    const userId = req.user.id;
    const userType = req.user.user_type;
    
    // Build query based on user type
    let query;
    let queryParams;
    
    if (userType === 'customer') {
      query = `
        SELECT o.*, m.business_name as merchant_name, u.name as customer_name
        FROM orders o
        JOIN merchants m ON o.merchant_id = m.id
        JOIN users u ON o.customer_id = u.id
        WHERE o.id = $1 AND o.customer_id = $2
      `;
      queryParams = [orderId, userId];
    } else if (userType === 'merchant') {
      query = `
        SELECT o.*, m.business_name as merchant_name, u.name as customer_name
        FROM orders o
        JOIN merchants m ON o.merchant_id = m.id
        JOIN users u ON o.customer_id = u.id
        WHERE o.id = $1 AND m.user_id = $2
      `;
      queryParams = [orderId, userId];
    } else if (userType === 'agent') {
      query = `
        SELECT o.*, m.business_name as merchant_name, u.name as customer_name
        FROM orders o
        JOIN merchants m ON o.merchant_id = m.id
        JOIN users u ON o.customer_id = u.id
        LEFT JOIN agents a ON o.agent_id = a.id
        WHERE o.id = $1 AND (o.agent_id IS NULL OR a.user_id = $2)
      `;
      queryParams = [orderId, userId];
    }
    
    const result = await pool.query(query, queryParams);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found or access denied' });
    }
    
    const order = result.rows[0];
    
    // Get items
    const itemsResult = await pool.query(
      `SELECT oi.*, p.name as product_name, p.image_url
       FROM order_items oi
       JOIN products p ON oi.product_id = p.id
       WHERE oi.order_id = $1`,
      [orderId]
    );
    order.items = itemsResult.rows;
    
    // Get status history
    const historyResult = await pool.query(
      `SELECT osh.*, u.name as changed_by_name
       FROM order_status_history osh
       JOIN users u ON osh.changed_by = u.id
       WHERE osh.order_id = $1
       ORDER BY osh.created_at ASC`,
      [orderId]
    );
    order.status_history = historyResult.rows;
    
    res.json(order);
  } catch (error) {
    console.error('Error fetching order details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Submit a review
app.post('/api/reviews', authenticateToken, authorize(['customer']), async (req, res) => {
  try {
    const { order_id, product_id, rating, comment } = req.body;
    const customer_id = req.user.id;
    
    // Verify order belongs to customer and is delivered
    const orderCheck = await pool.query(
      'SELECT status FROM orders WHERE id = $1 AND customer_id = $2',
      [order_id, customer_id]
    );
    
    if (orderCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found or not yours' });
    }
    
    if (!['delivered', 'collected'].includes(orderCheck.rows[0].status)) {
      return res.status(400).json({ message: 'Can only review completed orders' });
    }
    
    // Check if review already exists
    const reviewCheck = await pool.query(
      'SELECT id FROM reviews WHERE customer_id = $1 AND order_id = $2 AND product_id = $3',
      [customer_id, order_id, product_id]
    );
    
    if (reviewCheck.rows.length > 0) {
      return res.status(400).json({ message: 'You already reviewed this product for this order' });
    }
    
    // Create review
    const result = await pool.query(
      'INSERT INTO reviews (customer_id, product_id, order_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [customer_id, product_id, order_id, rating, comment]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating review:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// MERCHANT ROUTES

// Get merchant profile
app.get('/api/merchant/profile', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const userId = req.user.id;
    
    const result = await pool.query(
      'SELECT m.*, u.name, u.email, u.phone FROM merchants m JOIN users u ON m.user_id = u.id WHERE u.id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant profile not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching merchant profile:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update merchant profile
app.put('/api/merchant/profile', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const userId = req.user.id;
    const { business_name, description, address } = req.body;
    
    const result = await pool.query(
      'UPDATE merchants SET business_name = $1, description = $2, address = $3 WHERE user_id = $4 RETURNING *',
      [business_name, description, address, userId]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating merchant profile:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Upload merchant logo
app.post('/api/merchant/logo', authenticateToken, authorize(['merchant']), upload.single('logo'), async (req, res) => {
  try {
    const userId = req.user.id;
    const logoUrl = `${process.env.API_URL}/uploads/${req.file.filename}`;
    
    await pool.query(
      'UPDATE merchants SET logo_url = $1 WHERE user_id = $2',
      [logoUrl, userId]
    );
    
    res.json({ logo_url: logoUrl });
  } catch (error) {
    console.error('Error uploading logo:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create category
app.post('/api/categories', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const userId = req.user.id;
    const { name } = req.body;

    // Validate the input
    if (!name || name.trim().length === 0) {
      return res.status(400).json({ message: 'Category name is required' });
    }

    // Get merchant id
    const merchantResult = await pool.query(
      'SELECT id FROM merchants WHERE user_id = $1',
      [userId]
    );

    if (merchantResult.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant not found' });
    }

    const merchantId = merchantResult.rows[0].id;

    // Insert the new category into the database
    const result = await pool.query(
      'INSERT INTO categories (name, merchant_id) VALUES ($1, $2) RETURNING *',
      [name, merchantId]
    );

    // Return the created category
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating category:', error.message || error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get merchant categories
app.get('/api/merchant/categories', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Check if the user is a merchant
    const merchantResult = await pool.query(
      'SELECT id FROM merchants WHERE user_id = $1',
      [userId]
    );
    
    if (merchantResult.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant not found' });
    }
    
    const merchantId = merchantResult.rows[0].id;
    
    // Fetch the categories for the merchant
    const result = await pool.query(
      'SELECT * FROM categories WHERE merchant_id = $1',
      [merchantId]
    );
    
    if (result.rows.length === 0) {
      return res.status(200).json({});
    }
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching categories:', error.message || error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get category by id
app.get('/api/categories/:id', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const userId = req.user.id

    const categoryId = req.params.id

    const merchantResult = await pool.query(
      'SELECT id FROM merchants WHERE user_id = $1',
      [userId]
    );

    if (merchantResult.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant not found' });
    }

    const merchantId = merchantResult.rows[0].id;

    const result = await pool.query(
      'SELECT * FROM categories WHERE merchant_id = $1 AND id = $2',
      [merchantId, categoryId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No categories found' });
    }
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching categories:', error.message || error);
    res.status(500).json({ message: 'Server error' });
  }
})

// Edit a category
app.put('/api/categories/:id', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const { name } = req.body;
    const categoryId = req.params.id;

    const result = await pool.query(
      'UPDATE categories SET name = $1 WHERE id = $2 RETURNING *',
      [name, categoryId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Category not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating category:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a category
app.delete('/api/categories/:id', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const categoryId = req.params.id;

    const result = await pool.query(
      'DELETE FROM categories WHERE id = $1 RETURNING *',
      [categoryId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Category not found' });
    }

    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// Create product
app.post('/api/products', authenticateToken, authorize(['merchant']), upload.single('image'), async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, description, price, category_id } = req.body;
    const imageUrl = req.file ? `${process.env.API_URL}/uploads/${req.file.filename}` : null;
    
    // Get merchant id
    const merchantResult = await pool.query('SELECT id FROM merchants WHERE user_id = $1', [userId]);
    
    if (merchantResult.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant not found' });
    }
    
    const merchantId = merchantResult.rows[0].id;
    
    const result = await pool.query(
      'INSERT INTO products (merchant_id, category_id, name, description, price, image_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [merchantId, category_id || null, name, description, price, imageUrl]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get merchant products
app.get('/api/merchant/products', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const userId = req.user.id;
    
    const merchantResult = await pool.query(
      'SELECT id FROM merchants WHERE user_id = $1',
      [userId]
    );
    
    if (merchantResult.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant not found' });
    }
    
    const merchantId = merchantResult.rows[0].id;
    
    const result = await pool.query(
      `SELECT p.*, c.name as category_name
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.id
        WHERE p.merchant_id = $1`,
      [merchantId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/product/:id/clear-image', authenticateToken, authorize(['merchant']), async (req, res) => {
  const userId = req.user.id;
  const productId = req.params.id;
  
  console.log('Clearing image for product ID:', productId);  // Log productId

  const query = 'UPDATE products SET image_url = NULL WHERE id = $1';
  const values = [productId];

  try {
    const result = await pool.query(query, values);
    console.log('Result rowCount:', result.rowCount); // Log rowCount

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json({ message: 'Product image cleared successfully' });
  } catch (err) {
    console.error('Error clearing image:', err);  // Log error details
    res.status(500).json({ message: 'Error clearing image' });
  }
});

// Update product
app.put('/api/products/:id', authenticateToken, authorize(['merchant']), upload.none(), async (req, res) => {
  try {
    const userId = req.user.id;
    const productId = req.params.id;
    const { name, description, price, category_id, is_available, image_url } = req.body;

    // Handle image URL if provided
    let imagePath = null;

    if (image_url) {
      // Download the image from the URL
      imagePath = await downloadImageFromURL(image_url);
    }

    // Parse price and handle availability
    const parsedPrice = parseFloat(price);
    const available = is_available === 'false' ? false : Boolean(is_available);

    // Validate fields (allow description to be optional)
    if (!name?.trim() || isNaN(parsedPrice)) {
      return res.status(400).json({ message: 'Invalid input data. Name and Price are required.' });
    }

    // Check if the product belongs to the logged-in merchant
    const checkResult = await pool.query(
      `SELECT p.id, p.image_url FROM products p
       JOIN merchants m ON p.merchant_id = m.id
       WHERE p.id = $1 AND m.user_id = $2`,
      [productId, userId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found or not yours' });
    }

    // Use the new image URL if available, or retain the current one
    let imageUrl = checkResult.rows[0].image_url;

    if (imagePath) {
      imageUrl = `http://${req.get('host')}/uploads/${path.basename(imagePath)}`;
    }

    // Update the product in the database, with description as optional
    const result = await pool.query(
      `UPDATE products 
       SET name = $1, description = $2, price = $3, category_id = $4, is_available = $5, image_url = $6
       WHERE id = $7
       RETURNING *`,
      [name.trim(), description?.trim() || null, parsedPrice, category_id || null, available, imageUrl, productId]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ message: 'Server error', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
});



app.delete('/api/products/:id', authenticateToken, authorize(['merchant']), async (req, res) => {
  const productId = req.params.id;
  const userId = req.user.id;

  try {
    // Get merchant ID for the logged-in user
    const merchantResult = await pool.query(
      'SELECT id FROM merchants WHERE user_id = $1',
      [userId]
    );

    if (merchantResult.rows.length === 0) {
      return res.status(403).json({ message: 'Unauthorized: Merchant not found' });
    }

    const merchantId = merchantResult.rows[0].id;

    // Check if product exists and belongs to this merchant
    const productResult = await pool.query(
      'SELECT * FROM products WHERE id = $1 AND merchant_id = $2',
      [productId, merchantId]
    );

    if (productResult.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found or unauthorized' });
    }

    // Delete the product
    await pool.query('DELETE FROM products WHERE id = $1', [productId]);

    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/merchant/products/:pid', async (req, res) => {
  const productId = parseInt(req.params.pid, 10);

  if (isNaN(productId)) {
    return res.status(400).json({ message: 'Invalid product ID' });
  }

  try {
    const result = await pool.query('SELECT * FROM products WHERE id = $1', [productId]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Product not found' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Server error, please try again later' });
  }
});


// Get merchant orders
app.get('/api/merchant/orders', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const userId = req.user.id;
    const { status } = req.query;

    const merchantResult = await pool.query(
      'SELECT id FROM merchants WHERE user_id = $1',
      [userId]
    );

    if (merchantResult.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant not found' });
    }

    const merchantId = merchantResult.rows[0].id;

    let query = `
      SELECT o.*, u.name as customer_name
      FROM orders o
      JOIN users u ON o.customer_id = u.id
      WHERE o.merchant_id = $1
    `;

    const queryParams = [merchantId];

    if (status) {
      query += ' AND o.status = $2';
      queryParams.push(status);
    }

    query += ' ORDER BY o.created_at DESC';

    const result = await pool.query(query, queryParams);

    // Loop through the order items
    for (let order of result.rows) {
      const itemsResult = await pool.query(
        `SELECT oi.*, p.name as product_name
         FROM order_items oi
         JOIN products p ON oi.product_id = p.id
         WHERE oi.order_id = $1`,
        [order.id]
      );
      order.items = itemsResult.rows;
    }

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching merchant orders:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update order status (merchant)
app.put('/api/merchant/orders/:orderId/status', authenticateToken, authorize(['merchant']), async (req, res) => {
  const { orderId } = req.params;
  const { status, notes } = req.body;
  const userId = req.user?.id;

  console.log('🔄 PUT /api/merchant/orders/:orderId/status');
  console.log('➡️ Order ID:', orderId);
  console.log('📝 New Status:', status);
  console.log('🗒️ Notes:', notes);
  console.log('🔐 User ID:', userId);

  try {
    const validStatuses = ['pending', 'accepted', 'rejected', 'preparing', 'ready for collection', 'cancelled'];
    if (!validStatuses.includes(status)) {
      console.log('❌ Invalid status:', status);
      return res.status(400).json({ message: 'Invalid status' });
    }

    const orderQuery = 'SELECT * FROM orders WHERE id = $1';
    const orderResult = await pool.query(orderQuery, [orderId]);

    if (orderResult.rows.length === 0) {
      console.log('❌ Order not found:', orderId);
      return res.status(404).json({ message: 'Order not found' });
    }

    const order = orderResult.rows[0];
    console.log('📦 Current order status:', order.status);

    const current = order.status;
    const next = status;

    // Transition check
    const allowedTransitions = {
      pending: ['accepted', 'rejected', 'cancelled'],
      accepted: ['preparing', 'cancelled'],
      preparing: ['ready for collection', 'cancelled'],
    };

    if (
      current !== next &&
      !(allowedTransitions[current] && allowedTransitions[current].includes(next)) &&
      next !== 'cancelled'
    ) {
      console.log(`❌ Invalid transition from ${current} to ${next}`);
      return res.status(400).json({ message: `Cannot transition from ${current} to ${next}` });
    }

    const updateQuery = `
      UPDATE orders
      SET status = $1, notes = $2
      WHERE id = $3
      RETURNING *;
    `;
    const updatedOrderResult = await pool.query(updateQuery, [status, notes || order.notes, orderId]);

    const updatedOrder = updatedOrderResult.rows[0];
    console.log('✅ Order successfully updated:', updatedOrder);

    return res.status(200).json(updatedOrder);
  } catch (error) {
    console.error('🔥 Server error during status update:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});



// Get merchant reviews
app.get('/api/merchant/reviews', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const userId = req.user.id;
    
    const result = await pool.query(
      `SELECT r.*, p.name as product_name, u.name as customer_name
       FROM reviews r
       JOIN products p ON r.product_id = p.id
       JOIN users u ON r.customer_id = u.id
       JOIN merchants m ON p.merchant_id = m.id
       WHERE m.user_id = $1
       ORDER BY r.created_at DESC`,
      [userId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// New GET function to filter products by category ID
app.get('/api/products/category/:categoryId', authenticateToken, async (req, res) => { 
  try {
    const { categoryId } = req.params;

    // If the category is "All", fetch all products without filtering by category
    if (categoryId === 'All') {
      const result = await pool.query('SELECT * FROM products');
      return res.json(result.rows); // Send all products
    }

    // Query the database to get products by category ID if categoryId is not "All"
    const result = await pool.query(
      'SELECT * FROM products WHERE category_id = $1',
      [categoryId]
    );

    res.json(result.rows); // Send the filtered products
  } catch (error) {
    console.error('Error fetching products by category:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// AGENT ROUTES

// Update agent location
app.put(
  '/api/merchant/location/:id',
  authenticateToken,
  authorize(['merchant']), // Only merchants allowed
  async (req, res) => {
    try {
      const agentUserId = parseInt(req.params.id); // the agent's user_id
      const { lat, lng } = req.body;

      // Make sure the target user is actually an agent
      const checkAgent = await pool.query('SELECT * FROM users WHERE id = $1 AND user_type = $2', [agentUserId, 'agent']);
      if (checkAgent.rows.length === 0) {
        return res.status(404).json({ message: 'Agent not found' });
      }

      await pool.query(
        'UPDATE agents SET current_location_lat = $1, current_location_lng = $2, last_active = NOW() WHERE user_id = $3',
        [lat, lng, agentUserId]
      );

      res.json({ success: true, message: 'Agent location updated by merchant' });
    } catch (error) {
      console.error('Error updating agent location by merchant:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

app.post('/api/merchant/create-agent', authenticateToken, authorize(['merchant']), async (req, res) => {
  try {
    const { agent_name, agent_email, agent_phone, agent_password, lat, lng, location_name } = req.body;
    const merchant_id = req.user.id

    // Check if agent already exists
    const agentCheck = await pool.query('SELECT * FROM users WHERE email = $1 AND user_type = $2', [agent_email, 'agent']);
    if (agentCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Agent already exists' });
    }

    // Hash the agent's password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(agent_password, salt); // Hash the provided agent password

    // Create agent in the users table
    const newAgent = await pool.query(
      'INSERT INTO users (email, password, name, phone, user_type) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [agent_email, hashedPassword, agent_name, agent_phone, 'agent']
    );

    // Insert agent's location into agents table
    await pool.query(
      'INSERT INTO agents (user_id, current_location_lat, current_location_lng, merchant_id, location_name) VALUES ($1, $2, $3, $4, $5)',
      [newAgent.rows[0].id, lat, lng, merchant_id, location_name]
    );

    res.status(201).json({ message: 'Agent created successfully' });
  } catch (error) {
    console.error('Error creating agent:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


app.put(
  '/api/agent/location/:id',
  authenticateToken,
  authorize(['merchant']), // Only merchants allowed
  async (req, res) => {
    try {
      const agentUserId = parseInt(req.params.id); // the agent's user_id
      const { lat, lng } = req.body;

      // Make sure the target user is actually an agent
      const checkAgent = await pool.query('SELECT * FROM users WHERE id = $1 AND user_type = $2', [agentUserId, 'agent']);
      if (checkAgent.rows.length === 0) {
        return res.status(404).json({ message: 'Agent not found' });
      }

      await pool.query(
        'UPDATE agents SET current_location_lat = $1, current_location_lng = $2, last_active = NOW() WHERE user_id = $3',
        [lat, lng, agentUserId]
      );

      res.json({ success: true, message: 'Agent location updated by merchant' });
    } catch (error) {
      console.error('Error updating agent location by merchant:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);


app.put(
  '/api/agent/location/:id',
  authenticateToken,
  authorize(['agent']),
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { lat, lng } = req.body;

      // Ensure the user is updating only their own location
      if (req.user.id !== userId) {
        return res.status(403).json({ message: 'Unauthorized access' });
      }

      await pool.query(
        'UPDATE agents SET current_location_lat = $1, current_location_lng = $2, last_active = NOW() WHERE user_id = $3',
        [lat, lng, userId]
      );

      res.json({ success: true });
    } catch (error) {
      console.error('Error updating agent location:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Fetch businesses (merchants)
app.get('/businesses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, business_name FROM merchants');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching businesses' });
  }
});

// Fetch collection points (agents with location)
app.get('/collection-points', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, current_location_lat, current_location_lng, location_name FROM agents');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch collection points' });
  }
});



// Get available orders for collection
app.get('/api/agent/orders', authenticateToken, authorize(['agent']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, m.business_name, m.address, u.name as customer_name
       FROM orders o
       JOIN merchants m ON o.merchant_id = m.id
       JOIN users u ON o.customer_id = u.id
       WHERE o.status = 'ready for collection' AND o.agent_id IS NULL
       ORDER BY o.created_at ASC`
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching available orders:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get agent's assigned orders
app.get('/api/agent/my-orders', authenticateToken, authorize(['agent']), async (req, res) => {
  try {
    const userId = req.user.id;

    // Step 1: Check if the agent exists
    const agentResult = await pool.query(
      'SELECT id FROM agents WHERE user_id = $1',
      [userId]
    );
    
    if (agentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Agent not found' });
    }
    
    const agentId = agentResult.rows[0].id;

    // Step 2: Fetch orders for the agent
    const result = await pool.query(
      `SELECT o.*, m.business_name, m.address, u.name as customer_name
       FROM orders o
       JOIN merchants m ON o.merchant_id = m.id
       JOIN users u ON o.customer_id = u.id
       WHERE o.agent_id = $1 AND o.status IN ('accepted', 'preparing', 'ready for collection', 'collected')
       ORDER BY CASE 
         WHEN o.status = 'collected' THEN 1
         ELSE 0
       END, o.created_at ASC`,
      [agentId]
    );

    if (result.rows.length === 0) {
      return res.status(200).json({ message: 'No orders found for the agent.' });
    }

    // Step 3: Fetch items for each order
    for (let order of result.rows) {
      const itemsResult = await pool.query(
        `SELECT oi.*, p.name as product_name
         FROM order_items oi
         JOIN products p ON oi.product_id = p.id
         WHERE oi.order_id = $1`,
        [order.id]
      );

      // Log the items fetched for debugging
      console.log('Items for order', order.id, itemsResult.rows);
      
      // Add items to order
      order.items = itemsResult.rows;
    }

    // Step 4: Send response with orders and their items
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching agent orders:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Assign order to agent
app.post('/api/agent/orders/:id/assign', authenticateToken, authorize(['customer']), async (req, res) => {
  try {
    // const agentId = req.body.agentId;
    const agent = JSON.parse(req.body.agentData)
    const orderId = req.params.id;
    const userId = req.user.id

    console.log(agent.id)
    
    // For now, it will test if the agent id is 2
    if (agent.id === 2) {
      console.log('Agent ID passed correctly ');
    }
    const agentId = agent.id
    
    // Check if order is available
    const orderCheck = await pool.query(
      'SELECT status, agent_id FROM orders WHERE id = $1',
      [orderId]
    );
    
    if (orderCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    if (orderCheck.rows[0].status === 'rejected' || orderCheck.rows[0].status === 'cancelled') {
      return res.status(400).json({ message: 'Order is not ready for collection' });
    }
    
    if (orderCheck.rows[0].agent_id) {
      return res.status(400).json({ message: 'Order already assigned to an agent' });
    }
    
    // Assign order to agent
    const result = await pool.query(
      'UPDATE orders SET agent_id = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      [agentId, orderId]
    );
    
    // Record status history
    await pool.query(
      'INSERT INTO order_status_history (order_id, status, changed_by, notes) VALUES ($1, $2, $3, $4)',
      [orderId, 'assigned to agent', userId, 'Order assigned for collection']
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error assigning order:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify QR code and mark order as collected
app.post('/api/agent/orders/:id/collect', authenticateToken, authorize(['agent']), async (req, res) => {
  try {
    const userId = req.user.id;
    const orderId = req.params.id;
    const { qr_data } = req.body;
    
    // Parse QR data
    let qrInfo;
    try {
      qrInfo = JSON.parse(qr_data);
    } catch (e) {
      return res.status(400).json({ message: 'Invalid QR code data' });
    }
    
    if (qrInfo.order_id != orderId) { // Using loose equality intentionally
      return res.status(400).json({ message: 'QR code does not match this order' });
    }
    
    // Check if order is assigned to this agent
    const agentResult = await pool.query(
      'SELECT id FROM agents WHERE user_id = $1',
      [userId]
    );
    
    if (agentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Agent not found' });
    }
    
    const agentId = agentResult.rows[0].id;
    
    const orderCheck = await pool.query(
      'SELECT status, agent_id, customer_id FROM orders WHERE id = $1',
      [orderId]
    );
    
    if (orderCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    const order = orderCheck.rows[0];
    
    if (order.status !== 'ready for collection') {
      return res.status(400).json({ message: 'Order is not ready for collection' });
    }
    
    if (order.agent_id !== agentId) {
      return res.status(400).json({ message: 'Order is not assigned to you' });
    }
    
    if (order.customer_id != qrInfo.customer_id) { // Using loose equality intentionally
      return res.status(400).json({ message: 'QR code customer does not match order' });
    }
    
    // Mark as collected
    const result = await pool.query(
      'UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      ['collected', orderId]
    );
    
    // Record status history
    await pool.query(
      'INSERT INTO order_status_history (order_id, status, changed_by, notes) VALUES ($1, $2, $3, $4)',
      [orderId, 'collected', userId, 'Order collected by customer, verified via QR code']
    );
    
    // Notify customer and merchant (simplified)
    const notificationData = await pool.query(
      `SELECT 
        o.id as order_id,
        c.email as customer_email, 
        c.name as customer_name,
        m.business_name,
        mu.email as merchant_email
       FROM orders o
       JOIN users c ON o.customer_id = c.id
       JOIN merchants m ON o.merchant_id = m.id
       JOIN users mu ON m.user_id = mu.id
       WHERE o.id = $1`,
      [orderId]
    );
    
    if (notificationData.rows.length > 0) {
      const notification = notificationData.rows[0];
      
      // Email to customer
      const customerMailOptions = {
        from: process.env.EMAIL_USER,
        to: notification.customer_email,
        subject: `Order #${notification.order_id} Collected - Thank You!`,
        html: `
          <h1>Order Collected</h1>
          <p>Hello ${notification.customer_name},</p>
          <p>Your order #${notification.order_id} from ${notification.business_name} has been successfully collected.</p>
          <p>Enjoy your meal!</p>
        `
      };
      
      // Email to merchant
      const merchantMailOptions = {
        from: process.env.EMAIL_USER,
        to: notification.merchant_email,
        subject: `Order #${notification.order_id} Collected`,
        html: `
          <h1>Order Collected</h1>
          <p>Hello ${notification.business_name},</p>
          <p>Order #${notification.order_id} has been successfully collected by the customer.</p>
        `
      };
      
      transporter.sendMail(customerMailOptions);
      transporter.sendMail(merchantMailOptions);
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error processing collection:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/create-payment-intent', async (req, res) => {
  const { amount } = req.body; // amount should be in pennies (e.g., £10 = 1000)
  
  if (!amount || amount <= 0) {
    return res.status(400).send({ error: 'Amount must be greater than 0' });
  }

  try {
    // Create a Payment Intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'gbp', // You can change this to any other currency you support
      payment_method_types: ['card'], // Only card payments for now
    });

    // Send back the client secret
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: err.message });
  }
});

// Route to create a new customer setting
app.post('/customer-settings', authenticateToken, async (req, res) => {
  const { merchant_id, agent_id } = req.body;
  const customer_id = req.user.id

  try {
    const result = await pool.query(
      'INSERT INTO customer_settings (customer_id, merchant_id, agent_id) VALUES ($1, $2, $3) RETURNING *',
      [customer_id, merchant_id, agent_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating customer settings' });
  }
});

// Route to get customer settings by customer_id
app.get('/customer-settings/:customerId', authenticateToken, async (req, res) => {
  const { customerId } = req.params;

  try {
    const result = await pool.query(
      'SELECT * FROM customer_settings WHERE customer_id = $1',
      [customerId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Customer settings not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching customer settings' });
  }
});

// Route to update customer settings by customer_id
app.put('/customer-settings', authenticateToken, async (req, res) => {
  const { business_name, lat, lng } = req.body;
  const customerId = req.user
  try {
    // Find merchant by business_name
    const merchantResult = await pool.query(
      'SELECT id FROM merchants WHERE business_name = $1',
      [business_name]
    );
    if (merchantResult.rows.length === 0) {
      return res.status(404).json({ message: 'Merchant not found' });
    }
    const merchant_id = merchantResult.rows[0].id;

    // Find agent by lat/lng
    const agentResult = await pool.query(
      'SELECT id FROM agents WHERE current_location_lat = $1 AND current_location_lng = $2',
      [lat, lng]
    );
    if (agentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Agent not found' });
    }
    const agent_id = agentResult.rows[0].id;

    // Upsert the customer settings
    const result = await pool.query(
      `
      INSERT INTO customer_settings (customer_id, merchant_id, agent_id, updated_at)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
      ON CONFLICT (customer_id)
      DO UPDATE SET merchant_id = $2, agent_id = $3, updated_at = CURRENT_TIMESTAMP
      RETURNING *
      `,
      [customerId, merchant_id, agent_id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error saving customer settings' });
  }
});



// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});