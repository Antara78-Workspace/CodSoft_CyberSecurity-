const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// REGISTER USER
const registerUser = async (req, res) => {
try {
const { name, email, password } = req.body;


    if (!name || !email || !password) {
        return res.status(400).json({
            message: "Name, email and password are required"
        });
    }

    if (password.length < 8) {
        return res.status(400).json({
            message: "Password must contain at least 8 characters"
        });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await User.findOne({
        email: normalizedEmail
    });

    if (existingUser) {
        return res.status(409).json({
            message: "Email is already registered"
        });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
        name: name.trim(),
        email: normalizedEmail,
        password: hashedPassword,
        role: "user"
    });

    res.status(201).json({
        message: "Registration successful",
        user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role
        }
    });

} catch (error) {
    if (error.code === 11000) {
        return res.status(409).json({
            message: "Email is already registered"
        });
    }

    console.error("Registration error:", error.message);

    res.status(500).json({
        message: "Registration failed"
    });
}


};

// LOGIN USER
const loginUser = async (req, res) => {
try {
const { email, password } = req.body;


    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required"
        });
    }

    const normalizedEmail = email.trim().toLowerCase();

    console.log("Connected database:", User.db.name);
console.log("User collection:", User.collection.name);

const allUsers = await User.find({})
    .select("name email")
    .lean();

console.log("Total users found:", allUsers.length);
console.log("Users in database:", allUsers); 

   const user = await User.findOne({
    email: normalizedEmail
});

console.log("Login email:", normalizedEmail);
console.log("User found:", !!user);

if (!user) {
    return res.status(401).json({
        message: "Invalid email or password"
    });
}

    const isPasswordValid = await bcrypt.compare(
        password,
        user.password
    );

    console.log("Password matched:", isPasswordValid);

    if (!isPasswordValid) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    const token = jwt.sign(
        {
            userId: user._id.toString(),
            role: user.role
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    res.status(200).json({
        message: "Login successful",
        token,
        user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role
        }
    });

} catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
        message: "Login failed"
    });
}


};

module.exports = {
registerUser,
loginUser
};
