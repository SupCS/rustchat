import { renderLogin } from "./login.js";
import { fetchWithAuth } from "./utils.js";

export function renderMainPage() {
    const app = document.getElementById("app");
    if (!app) {
        console.error("#app element not found in DOM.");
    } else {
        console.log("#app found:", app);
    }

    app.className = "main";

    app.innerHTML = `
        <div id="topbar">
            Logged in as: <span id="username">Loading...</span>
            <button id="logout-button" style="margin-left: 20px;">Logout</button>
        </div>
        <div id="main-container">
            <div id="sidebar">
                <h3>Chats</h3>
                <ul id="chat-list">Loading...</ul>
            </div>
            <div id="chat-area">
                <h2>Select a chat to start messaging</h2>
                <div id="message-list"></div>
                <form id="message-form" style="display: none;">
                    <input type="text" id="message-input" placeholder="Type a message" required />
                    <button type="submit">Send</button>
                </form>
            </div>
        </div>
    `;

    setupLogoutHandler();

    const token = localStorage.getItem("token");

    loadCurrentUser(token);
    loadChatList(token);
}

function setupLogoutHandler() {
    const logoutButton = document.getElementById("logout-button");
    logoutButton.addEventListener("click", () => {
        localStorage.removeItem("token");
        renderLogin();
    });
}

async function loadCurrentUser(token) {
    try {
        const response = await fetchWithAuth(
            "http://127.0.0.1:3030/current_user",
            token
        );
        const data = await response.json();
        document.getElementById("username").textContent = data.username;
    } catch (error) {
        console.error("Error fetching current user:", error);
    }
}

async function loadChatList(token) {
    console.log("Attempting to load chat list...");
    try {
        const response = await fetchWithAuth(
            "http://127.0.0.1:3030/chats",
            token
        );
        const data = await response.json();
        console.log("Response from API:", data);

        if (!Array.isArray(data.chats)) {
            throw new Error(
                "Invalid response format: chats should be an array."
            );
        }

        const chatList = document.getElementById("chat-list");
        if (!chatList) {
            console.error("#chat-list not found in DOM.");
            return;
        }

        chatList.innerHTML = ""; // Очищуємо список перед додаванням

        data.chats.forEach((chat) => {
            const li = document.createElement("li");
            li.textContent = chat;
            li.dataset.chatPartner = chat;

            console.log(`Adding click listener for chat: ${chat}`);
            li.addEventListener("click", () => {
                console.log(`Clicked on chat: ${chat}`);
                loadChatHistory(chat, token);
            });

            chatList.appendChild(li);
        });

        console.log("Chat list successfully rendered.");
    } catch (error) {
        console.error("Error fetching chat list:", error);
    }
}

async function loadChatHistory(partner, token) {
    console.log("Loading chat history for:", partner);
    try {
        const response = await fetchWithAuth(
            `http://127.0.0.1:3030/messages?partner=${partner}`,
            token
        );
        const messages = await response.json();

        if (!Array.isArray(messages)) {
            throw new Error(
                "Invalid response format: messages should be an array."
            );
        }

        const messageList = document.getElementById("message-list");
        messageList.innerHTML = ""; // Очищаємо список повідомлень перед додаванням

        if (messages.length === 0) {
            messageList.classList.remove("visible"); // Ховаємо, якщо немає повідомлень
        } else {
            messageList.classList.add("visible"); // Показуємо, якщо є повідомлення

            messages.forEach((message) => {
                const div = document.createElement("div");
                div.className =
                    message.sender === partner ? "received" : "sent";
                div.textContent = `${message.sender}: ${message.content}`;
                messageList.appendChild(div);
            });
        }

        // Показуємо форму для відправки повідомлень
        const messageForm = document.getElementById("message-form");
        const messageInput = document.getElementById("message-input");
        messageForm.style.display = "flex";

        messageForm.onsubmit = async (e) => {
            e.preventDefault(); // Забороняємо перезавантаження сторінки
            const content = messageInput.value.trim();
            if (!content) return;

            await sendMessage(partner, content, token);
            messageInput.value = ""; // Очищаємо поле вводу
            await loadChatHistory(partner, token); // Перезавантажуємо історію чату
        };

        console.log("Chat history loaded successfully.");
    } catch (error) {
        console.error("Error loading chat history:", error);
    }
}

async function sendMessage(receiver, content, token) {
    console.log("Sending message to:", receiver);
    try {
        const sender = document.getElementById("username").textContent; // Отримуємо ім'я відправника
        const timestamp = new Date().toISOString(); // Генеруємо поточний час у форматі ISO

        const body = {
            sender,
            receiver,
            content,
            timestamp,
        };

        console.log("Message body:", body);

        const response = await fetchWithAuth(
            "http://127.0.0.1:3030/messages",
            token,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            }
        );

        if (!response.ok) {
            const errorText = await response.text();
            console.error("Error response from server:", errorText);
            throw new Error(`Failed to send message: ${response.statusText}`);
        }

        console.log("Message sent successfully.");
    } catch (error) {
        console.error("Error sending message:", error);
    }
}
