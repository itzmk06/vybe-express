const bcrypt = require('bcrypt');
const express = require('express');
const jwt = require('jsonwebtoken');
const { verifySignUpData } = require('../utils/validation');
const { User } = require('../models/User');
const { userAuth } = require('../middlewares/authMiddleware');

const authRouter = express.Router();

const setAuthCookies = (res, token, refreshToken) => {
    res.cookie("token", token, {
        // httpOnly: true,  
        secure: false,   
        sameSite: "Lax", 
        expires: new Date(Date.now() + 60 * 60 * 1000) 
    });

    res.cookie("refresh_token", refreshToken, {
        // httpOnly: true,
        secure: false,
        sameSite: "Lax",
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) 
    });
};


authRouter.post('/signup', async (req, res) => {
    try {
        verifySignUpData(req);
        const { userName, firstName, lastName, emailId, password } = req.body;

        const existingUser = await User.findOne({ emailId });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            userName,
            firstName,
            lastName,
            emailId,
            password: hashedPassword
        });

        const savedUser = await user.save();

        const token = await savedUser.getAccessToken();
        const refreshToken = await savedUser.getRefreshToken();
        savedUser.refreshToken = refreshToken;
        await savedUser.save();

        setAuthCookies(res, token, refreshToken);

        const { password: pass, refreshToken: refToken, __v, ...userDetails } = savedUser.toObject();

        return res.status(201).json({ message: 'User registered successfully!', data: userDetails });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

authRouter.post('/login', async (req, res) => {
    try {
        const { emailId, password } = req.body;
        const user = await User.findOne({ emailId });

        if (!user || !(await user.validatePassword(password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = await user.getAccessToken();
        const refreshToken = await user.getRefreshToken();
        user.refreshToken = refreshToken;
        await user.save();

        setAuthCookies(res, token, refreshToken);

        const { password: pass, refreshToken: refToken, __v, ...userDetails } = user.toObject();

        return res.status(200).json({ message: 'Logged in successfully!', data: userDetails });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

authRouter.post('/refreshToken', async (req, res) => {
    try {
        const { refresh_token } = req.cookies;
        if (!refresh_token) return res.status(401).json({ message: 'Refresh token not found!' });

        const decoded = jwt.verify(refresh_token, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decoded._id);

        if (!user || user.refreshToken !== refresh_token) {
            return res.status(403).json({ message: 'Invalid refresh token!' });
        }

        const newAccessToken = await user.getAccessToken();
        setAuthCookies(res, newAccessToken, refresh_token);

        return res.status(200).json({ message: 'Access token refreshed!' });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

authRouter.post('/logout', async (req, res) => {
    try {
        const { refresh_token } = req.cookies;
        if (!refresh_token) return res.status(400).json({ message: 'No refresh token found!' });

        const user = await User.findOne({ refreshToken: refresh_token });
        if (user) {
            user.refreshToken = null;
            await user.save();
        }
        res.clearCookie("token", { httpOnly: true, secure: true, sameSite: "Lax" });
        res.clearCookie("refresh_token", { httpOnly: true, secure: true, sameSite: "Lax" });
      
        return res.status(200).json({ message: 'Logged out successfully!' });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

authRouter.get('/user',userAuth,async(req,res)=>{
    res.status(200).json({
        message:'User authenticated!',
        data:req.user
    })
})

module.exports = { authRouter };
