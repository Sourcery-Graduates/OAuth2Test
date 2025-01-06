function togglePasswordVisibility() {
    const passwordInput = document.getElementById("password");
    const passwordIcon = document.querySelector(".toggle-password");
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        passwordIcon.textContent = "🙈";
    } else {
        passwordInput.type = "password";
        passwordIcon.textContent = "👁️";
    }
}

function redirectToRegister() {
    // Replace with the actual frontend URL
    window.location.href = "https://frontend.example.com/register";
}
