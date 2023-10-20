const express = require("express");
require("express-async-errors");
const path = require("path");
const exphbs = require("express-handlebars");
const cookieParser = require("cookie-parser");
const cors = require("cors");
require("dotenv").config();

const PORT = process.env.PORT || 5000;

const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser());

const publicDirectory = path.join(__dirname, "./public");
app.use(express.static(publicDirectory));

app.use(express.urlencoded({ extended: false }));

const handlebars = exphbs.create({ extname: ".hbs" });
app.engine(".hbs", handlebars.engine);
app.set("view engine", "hbs");

app.use("/", require("./routes/pages"));

app.use("/api", require("./routes/api"));

app.use((req, res) => res.status(404).render("404"));
app.use((err, req, res, next) => res.status(500).render("500"));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
