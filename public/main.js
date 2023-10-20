const visibilityToggle = document.querySelectorAll(".visibility-toggle");
visibilityToggle.forEach((item) => {
    item.addEventListener("click", () => {
        if (item.classList.contains("showed")) {
            item.classList.remove("showed");
            item.parentElement.querySelector("input").type = "password";
        } else {
            item.classList.add("showed");
            item.parentElement.querySelector("input").type = "text";
        }
    });
});

const formButton = document.querySelectorAll(".form-button");
formButton.forEach((item) => {
    item.addEventListener("click", () => {
        item.innerHTML = `<span class="loading"><i class="dot"></i><i class="dot"></i><i class="dot"></i></span>`;
        item.disabled = true;
        document.forms.form.submit();
    });
});

const passwordField = document.getElementById("password");
const passwordConfirmField = document.getElementById("passwordConfirm");
const formWarning = document.getElementById("form-warning");
const lengthCheck = document.getElementById("lengthCheck");
const numberCheck = document.getElementById("numberCheck");
const letterCheck = document.getElementById("letterCheck");
const capitalCheck = document.getElementById("capitalCheck");

passwordConfirmField &&
    passwordField.addEventListener("keyup", () => {
        validatePassword();
        passwordConfirmMatch();
    });

passwordConfirmField &&
    passwordConfirmField.addEventListener("keyup", passwordConfirmMatch);

function validatePassword() {
    // Validate lowercase letters
    var lowerCaseLetters = /[a-z]/g;
    if (passwordField.value.match(lowerCaseLetters)) {
        letterCheck.classList.add("valid");
    } else {
        letterCheck.classList.remove("valid");
    }

    // Validate capital letters
    var upperCaseLetters = /[A-Z]/g;
    if (passwordField.value.match(upperCaseLetters)) {
        capitalCheck.classList.add("valid");
    } else {
        capitalCheck.classList.remove("valid");
    }

    // Validate numbers
    var numbers = /[0-9]/g;
    if (passwordField.value.match(numbers)) {
        numberCheck.classList.add("valid");
    } else {
        numberCheck.classList.remove("valid");
    }

    // Validate length
    if (passwordField.value.length >= 8) {
        lengthCheck.classList.add("valid");
    } else {
        lengthCheck.classList.remove("valid");
    }
}

function passwordConfirmMatch() {
    if (passwordConfirmField.value !== passwordField.value) {
        formWarning.innerHTML = `<i class="icon"><svg
                aria-hidden="true"
                focusable="false"
                data-prefix="fas"
                data-icon="circle-exclamation"
                role="img"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 512 512"
                data-fa-i2svg=""
            >
                <path
                    fill="currentColor"
                    d="M256 512A256 256 0 1 0 256 0a256 256 0 1 0 0 512zm0-384c13.3 0 24 10.7 24 24V264c0 13.3-10.7 24-24 24s-24-10.7-24-24V152c0-13.3 10.7-24 24-24zM224 352a32 32 0 1 1 64 0 32 32 0 1 1 -64 0z"
                ></path>
            </svg></i>As senhas digitadas não são iguais`;
    } else {
        formWarning.innerHTML = "";
    }
}

function closeButton(element) {
    element.parentElement.remove();
}
