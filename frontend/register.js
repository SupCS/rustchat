import { renderLogin } from "./login.js";

export function renderRegister() {
    const app = document.getElementById("app");

    app.innerHTML = `
        <h2>Register</h2>
        <form id="register-form">
            <input type="text" id="username" placeholder="Username" required />
            <input type="password" id="password" placeholder="Password" required />
            <button type="submit">Register</button>
        </form>
        <p id="error-message" style="color: red; display: none;"></p>
        <button id="back-to-login">Back to Login</button>
    `;

    const form = document.getElementById("register-form");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        try {
            const response = await fetch("http://127.0.0.1:3030/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            if (response.ok) {
                alert("Registration successful! You can now login.");
                renderLogin(); // Повернення до сторінки логіну
            } else {
                document.getElementById("error-message").textContent =
                    "User already exists or invalid data.";
                document.getElementById("error-message").style.display =
                    "block";
            }
        } catch (error) {
            console.error("Error during registration:", error);
            document.getElementById("error-message").textContent =
                "An error occurred. Please try again.";
            document.getElementById("error-message").style.display = "block";
        }
    });

    const backToLoginButton = document.getElementById("back-to-login");
    backToLoginButton.addEventListener("click", () => {
        renderLogin(); // Повернення до логіну
    });
}
