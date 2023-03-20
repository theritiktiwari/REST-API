const express = require('express');
const cors = require("cors");
const dotenv = require('dotenv');
const connectDB = require('./config/connectDB');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const port = process.env.PORT || 5000;
connectDB();

app.get('/', (req, res) => {
    res.send('REST API Example');
});

app.use("/api/auth", require("./routes/auth"));

app.listen(port, () => {
    console.log(`Server is running on port ${port}...`);
});

module.exports = app;