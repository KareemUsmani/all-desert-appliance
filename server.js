require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const connectDB = require('./config/db');

const routes = require('./routes');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Database
connectDB();

// Routes
app.use('/api', routes);

app.listen(3000, () => {
    console.log('Server running on port 3000');
});