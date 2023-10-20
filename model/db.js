const mysql = require("mysql2/promise");

exports.start = mysql.createPool({
    host: process.env.DB_BASE_URL,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});
