const express = require("express");
const url = require("url");
const authController = require("../controllers/auth");
const router = express.Router();

router.get("/", authController.isLoggedIn, (req, res) => {
    const data = url.parse(req.url, true).query;
    const params = new URLSearchParams({
        ...data,
    });
    if (!req.user) {
        return res.redirect(`/login?${params}`);
    }
    res.redirect(
        `${
            req.protocol +
            "://" +
            (data.utm_source ? data.utm_source + "." : "") +
            process.env.MAIN_DOMAIN
        }`
    );
});

router.get("/login", authController.isLoggedIn, (req, res) => {
    const params = new URLSearchParams({
        ...url.parse(req.url, true).query,
    });
    if (!req.user) {
        return res.render("login", {
            url: req.url,
        });
    }
    res.redirect(`/?${params}`);
});

router.post("/login", authController.login);

router.get("/register", authController.isLoggedIn, (req, res) => {
    if (!req.user) {
        return res.render("register");
    }
    res.redirect("/");
});

router.post("/register", authController.register);

router.get("/forgot-password", authController.isLoggedIn, (req, res) => {
    if (!req.user) {
        return res.render("forgot");
    }
    res.redirect("/");
});

router.post("/forgot-password", authController.forgotPassword);

router.get(
    "/forgot-password/:token",
    authController.isLoggedIn,
    authController.recoveryPassword,
    (req, res) => {
        if (!req.user) {
            return res.render("forgot");
        }
        res.redirect("/");
    }
);

router.post("/forgot-password/:token", authController.resetPassword);

router.get("/logout", authController.logout);

module.exports = router;
