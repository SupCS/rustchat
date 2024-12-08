import { renderMainPage } from "./main.js";

export function renderLogin() {
    const app = document.getElementById("app");
    app.className = "login";

    app.innerHTML = `
        <h2>Login</h2>
        <form id="login-form">
            <input type="text" id="username" placeholder="Username" required />
            <input type="password" id="password" placeholder="Password" required />
            <button type="submit">Login</button>
        </form>
        <p id="error-message" style="color: red; display: none;"></p>
        <button id="register-button">Register</button>
    `;

    const form = document.getElementById("login-form");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        try {
            const response = await fetch("http://127.0.0.1:3030/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            if (response.ok) {
                const data = await response.json();
                localStorage.setItem("token", data.token);
                renderMainPage(); // Переходимо на головну сторінку
            } else {
                document.getElementById("error-message").textContent =
                    "Invalid login credentials.";
                document.getElementById("error-message").style.display =
                    "block";
            }
        } catch (error) {
            console.error("Error during login:", error);
            document.getElementById("error-message").textContent =
                "An error occurred. Please try again.";
            document.getElementById("error-message").style.display = "block";
        }
    });

    const registerButton = document.getElementById("register-button");
    registerButton.addEventListener("click", () => {
        import("./register.js").then(({ renderRegister }) => {
            renderRegister();
        });
    });
}
