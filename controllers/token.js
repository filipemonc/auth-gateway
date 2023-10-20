const crypto = require("crypto");
const querys = require("../model/querys");

exports.generate = async () => {
    const token = crypto.randomBytes(16).toString("hex");
    const results = await querys.getUserByRecoveryToken(token);
    if (results.length === 0) {
        return token;
    }
    return this.generate();
};
