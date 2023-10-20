exports.passwordRequirements = (password) => {
    var lowerCaseLetters = /[a-z]/g;
    var upperCaseLetters = /[A-Z]/g;
    var numbers = /[0-9]/g;
    if (!password.match(lowerCaseLetters)) return false;
    if (!password.match(upperCaseLetters)) return false;
    if (!password.match(numbers)) return false;
    if (!password.length >= 8) return false;
    return true;
};
