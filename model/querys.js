const db = require("./db");

exports.getUserByEmail = async (email) => {
    const [query] = await db.start.query(
        "SELECT * FROM users WHERE email = ?",
        [email]
    );
    return query;
};

exports.getUserById = async (id) => {
    const [query] = await db.start.query(
        "SELECT * FROM users WHERE user_id = ?",
        [id]
    );
    return query;
};

exports.createUser = async (name, email, password) => {
    const [query] = await db.start.query("INSERT INTO users SET ?", {
        name: name,
        email: email,
        password: password,
    });
    const item = await this.getUserById(query.insertId);
    return item;
};

exports.getUserByRecoveryToken = async (token) => {
    const [query] = await db.start.query(
        "SELECT * FROM users WHERE recovery_token = ?",
        [token]
    );
    return query;
};

exports.updateUserPasswordAndRecoveryToken = async (
    id,
    password,
    token,
    locked
) => {
    const [query] = await db.start.query(
        "UPDATE users SET password = ?, recovery_token = ?, locked = ? WHERE user_id = ?",
        [password, token, locked, id]
    );
    return query;
};
