import { renderLogin } from "./login.js";
import { renderMainPage } from "./main.js";
import { fetchWithAuth } from "./utils.js";

// Ініціалізація програми
async function initializeApp() {
    const token = localStorage.getItem("token");

    if (token) {
        const isTokenValid = await verifyToken(token);
        if (isTokenValid) {
            console.log("Calling renderMainPage...");
            renderMainPage();
            return;
        }
    }

    // Якщо токен недійсний або його немає, показуємо логін
    renderLogin();
}

async function verifyToken(token) {
    try {
        const response = await fetchWithAuth(
            "http://127.0.0.1:3030/current_user",
            token
        );
        return response.ok;
    } catch (error) {
        console.error("Error verifying token:", error);
        return false;
    }
}

initializeApp();
