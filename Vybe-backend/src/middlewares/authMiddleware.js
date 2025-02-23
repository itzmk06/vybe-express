const jwt = require("jsonwebtoken");
const { User } = require("../models/user");

const userAuth = async (req, res, next) => {
    try {
        const token = req.cookies?.token;
        if (!token) {
            return res.status(400).json({ message: "Unauthorized! Please log in." });
        }

        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        const user = await User.findById(decoded._id);
        if (!user) {
            return res.status(404).json({ message: "User not found! Please log in again." });
        }

        req.user = user;

        next();
    } catch (error) {
        console.error("Auth Middleware Error:", error.message);
        return res.status(400).json({ message: "Invalid or expired token! Please log in again." });
    }
};

module.exports = { userAuth };
