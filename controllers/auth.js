const url = require("url");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { promisify } = require("util");
const needle = require("needle");
const querys = require("../model/querys");
const validateController = require("./validate");
const newToken = require("./token");

const MAIN_DOMAIN = process.env.MAIN_DOMAIN.split(":")[0];
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

exports.login = async (req, res) => {
    const params = new URLSearchParams({
        ...url.parse(req.url, true).query,
    });
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).render("login", {
            email: email,
            message: "Please enter your e-mail and password",
            url: req.url,
        });
    }
    const results = await querys.getUserByEmail(email);
    if (results.length === 0) {
        return res.status(401).render("login", {
            email: email,
            message: "E-mail not registered",
            url: req.url,
        });
    }
    const isMatch = await bcrypt.compare(password, results[0].password);
    const isLocked = results[0].locked;
    if (isLocked) {
        return res.status(403).render("login", {
            email: email,
            message: "A new password has been requested for this e-mail",
            url: req.url,
        });
    }
    if (!results || !isMatch) {
        return res.status(401).render("login", {
            email: email,
            message: "Incorrect e-mail and/or password",
            url: req.url,
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
        domain: MAIN_DOMAIN,
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        httpOnly: true,
    };
    res.cookie("jwt", token, cookieOptions);
    res.status(200).redirect(`/?${params}`);
};

exports.register = async (req, res) => {
    const { name, email, password, passwordConfirm } = req.body;
    if (!name || !email || !password || !passwordConfirm) {
        return res.status(400).render("register", {
            name: name,
            email: email,
            message: "Please fill in all fields",
        });
    }
    if (password !== passwordConfirm) {
        return res.status(400).render("register", {
            name: name,
            email: email,
            message: "The passwords entered are not the same",
        });
    }
    const results = await querys.getUserByEmail(email);
    if (results.length > 0) {
        return res.status(409).render("register", {
            name: name,
            email: email,
            message: "E-mail already registered",
        });
    }
    const isValid = validateController.passwordRequirements(password);
    if (!isValid) {
        return res.status(400).render("register", {
            name: name,
            email: email,
            message: "The password entered does not meet the requirements",
        });
    }
    let hashedPassword = await bcrypt.hash(password, 8);
    const result = await querys.createUser(name, email, hashedPassword);
    const user_id = result[0].user_id;
    const token = jwt.sign(
        { user_id, name, email },
        process.env.JWT_ACCESS_SECRET,
        {
            expiresIn: process.env.JWT_EXPIRES_IN,
        }
    );
    const cookieOptions = {
        domain: MAIN_DOMAIN,
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        httpOnly: true,
    };
    res.cookie("jwt", token, cookieOptions);
    res.status(201).redirect("/");
};

exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).render("forgot", {
            email: email,
            message: "Please enter your registered e-mail",
        });
    }
    const results = await querys.getUserByEmail(email);
    if (results.length === 0) {
        return res.status(401).render("forgot", {
            email: email,
            message: "E-mail not registered",
        });
    }
    const user_id = results[0].user_id;
    const name = results[0].name.split(" ")[0];
    const token = await newToken.generate();
    const result = await querys.updateUserPasswordAndRecoveryToken(
        user_id,
        "locked",
        token,
        1
    );
    if (!result.changedRows) {
        res.status(400).render("forgot", {
            message:
                "An error occurred while recovering password, please try again",
        });
    }
    const options = {
        headers: {
            Authorization: `Bearer ${process.env.CROSS_DOMAIN_API_KEY}`,
        },
    };
    const message = {
        email: email,
        name: name,
        token: token,
    };
    const apiRes = await needle(
        "post",
        `${req.protocol}://email.${process.env.MAIN_DOMAIN}/api/sender`,
        message,
        options
    );
    if (apiRes.statusCode === 200) {
        return res.status(200).render("forgot", {
            message: "Recovery e-mail sent successfully",
        });
    }
    res.status(500).render("forgot", {
        message:
            "An error occurred while recovering password, please try again",
    });
};

exports.recoveryPassword = async (req, res) => {
    const results = await querys.getUserByRecoveryToken(req.params.token);
    if (results.length === 0) {
        return res.status(404).render("404");
    }
    const name = results[0].name.split(" ")[0];
    res.status(200).render("recovery", {
        name: name,
        token: req.params.token,
    });
};

exports.resetPassword = async (req, res) => {
    if (!req.params.token) {
        return res.status(404).render("404");
    }
    const { password, passwordConfirm } = req.body;
    const results = await querys.getUserByRecoveryToken(req.params.token);
    if (results.length === 0) {
        return res.status(404).render("404");
    }
    const user_id = results[0].user_id;
    const name = results[0].name.split(" ")[0];
    if (!password || !passwordConfirm) {
        return res.status(400).render("recovery", {
            name: name,
            token: req.params.token,
            message: "Por favor, preencha todos os campos",
        });
    }
    if (password !== passwordConfirm) {
        return res.status(400).render("recovery", {
            name: name,
            token: req.params.token,
            message: "The passwords entered are not the same",
        });
    }
    const isValid = validateController.passwordRequirements(password);
    if (!isValid) {
        return res.status(400).render("recovery", {
            name: name,
            token: req.params.token,
            message: "The password entered does not meet the requirements",
        });
    }
    let hashedPassword = await bcrypt.hash(password, 8);
    const result = await querys.updateUserPasswordAndRecoveryToken(
        user_id,
        hashedPassword,
        null,
        0
    );
    if (!result.changedRows) {
        res.status(400).render("recovery", {
            name: name,
            token: req.params.token,
            message:
                "An error occurred while resetting your password, please try again",
        });
    }
    res.status(200).render("login", {
        message: "Password changed successfully",
        url: "/login",
    });
};

exports.logout = (req, res) => {
    const params = new URLSearchParams({
        ...url.parse(req.url, true).query,
    });
    res.cookie("jwt", "loggedout", {
        domain: MAIN_DOMAIN,
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
    });
    res.status(200).redirect(`/?${params}`);
};

exports.isLoggedIn = async (req, res, next) => {
    if (req.cookies.jwt) {
        try {
            const decoded = await promisify(jwt.verify)(
                req.cookies.jwt,
                JWT_ACCESS_SECRET
            );
            const result = await querys.getUserById(decoded.user_id);
            if (!result) {
                return next();
            }
            req.user = result[0];
            return next();
        } catch (err) {
            return next();
        }
    }
    next();
};

exports.isTokenValid = async (token) => {
    try {
        const decoded = await promisify(jwt.verify)(token, JWT_ACCESS_SECRET);
        return decoded;
    } catch (err) {
        return false;
    }
};
