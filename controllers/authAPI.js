const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const querys = require("../model/querys");
const authController = require("./auth");
const validateController = require("./validate");

exports.login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).render("login", {
            message: "Please enter your e-mail and password",
        });
    }
    const results = await querys.getUserByEmail(email);
    if (results.length === 0) {
        return res.status(401).json({
            message: "E-mail not registered",
        });
    }
    const isMatch = await bcrypt.compare(password, results[0].password);
    const isLocked = results[0].locked;
    if (isLocked) {
        return res.status(403).json({
            message: "A new password has been requested for this e-mail",
        });
    }
    if (!results || !isMatch) {
        return res.status(401).json({
            message: "Incorrect e-mail and/or password",
        });
    }
    const user_id = results[0].user_id;
    const name = results[0].name;
    const token = jwt.sign(
        { user_id, name, email },
        process.env.JWT_ACCESS_SECRET,
        {
            expiresIn: process.env.JWT_EXPIRES_IN,
        }
    );
    const cookieOptions = {
        domain: process.env.MAIN_DOMAIN,
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        httpOnly: true,
    };
    res.cookie("jwt", token, cookieOptions);
    res.sendStatus(200);
};

exports.changePassword = async (req, res) => {
    const token = req.cookies.jwt;
    if (!token) {
        return res.sendStatus(401);
    }
    const isAuth = await authController.isTokenValid(token);
    if (!isAuth) {
        return res.sendStatus(401);
    }
    const { passwordCurrent, password, passwordConfirm } = req.body;
    if (!passwordCurrent || !password || !passwordConfirm) {
        return res.status(400).json({
            message: "Please fill in all fields",
        });
    }
    if (password !== passwordConfirm) {
        return res.status(400).json({
            message: "The passwords entered are not the same",
        });
    }
    const isValid = validateController.passwordRequirements(password);
    if (!isValid) {
        return res.status(400).json({
            message: "The password entered does not meet the requirements",
        });
    }
    const results = await querys.getUserById(isAuth.user_id);
    const isMatch = await bcrypt.compare(passwordCurrent, results[0].password);
    if (!isMatch) {
        return res.status(401).json({
            message: "The current password entered is incorrect",
        });
    }
    let hashedPassword = await bcrypt.hash(password, 8);
    const result = await querys.updateUserPasswordAndRecoveryToken(
        isAuth.user_id,
        hashedPassword,
        null,
        0
    );
    if (!result.changedRows) {
        res.status(400).json({
            message:
                "An error occurred while resetting your password, please try again",
        });
    }
    res.status(200).json({
        message: "Password changed successfully",
    });
};

exports.logout = (req, res) => {
    res.cookie("jwt", "loggedout", {
        domain: process.env.MAIN_DOMAIN,
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
    });
    res.sendStatus(200);
};
