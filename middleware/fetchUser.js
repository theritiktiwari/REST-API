const jwt = require('jsonwebtoken');

const fetchUser = (req, res, next) => {

    // Get the token from the header
    const token = req.header('auth-token');
    if (!token) {
        res.status(401).json({
            type: "error",
            message: "Invalid Credentials."
        });
    }
    // Get the user from the JWT token and add the user ID to the req object
    try {
        const data = jwt.verify(token, process.env.JWT_SECRET_KEY);
        req.user = data.user;
        next();
    } catch (error) {
        res.status(500).json({
            type: "error",
            message: "Something went wrong."
        });
    }
}

module.exports = fetchUser;