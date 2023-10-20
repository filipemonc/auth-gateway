const express = require("express");
const authController = require("../controllers/authAPI");
const router = express.Router();

router.post("/login", authController.login);
router.post("/change-password", authController.changePassword);
router.post("/logout", authController.logout);

module.exports = router;
