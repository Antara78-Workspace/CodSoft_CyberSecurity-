const API_BASE = "http://localhost:5000/api/auth";

const messageBox = document.getElementById("messageBox");

function showMessage(message, type) {
    messageBox.innerHTML = `
        <div class="alert alert-${type}" role="alert">
            ${message}
        </div>
    `;
}


// REGISTER USER

const registerForm = document.getElementById("registerForm");

if (registerForm) {

    registerForm.addEventListener("submit", async function (e) {

        e.preventDefault();

        const name = document.getElementById("name").value.trim();
        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value;

        const registerBtn = document.getElementById("registerBtn");

        registerBtn.disabled = true;
        registerBtn.innerText = "Creating Account...";

        try {

            const response = await fetch(`${API_BASE}/register`, {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    name,
                    email,
                    password
                })

            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || "Registration failed");
            }

            showMessage(
                "Registration successful! Redirecting to login...",
                "success"
            );

            registerForm.reset();

            setTimeout(() => {
                window.location.href = "login.html";
            }, 1500);

        } catch (error) {

            showMessage(error.message, "danger");

        } finally {

            registerBtn.disabled = false;
            registerBtn.innerHTML = 'Create Account <i class="bi bi-arrow-right"></i>';

        }

    });

}


// LOGIN USER

const loginForm = document.getElementById("loginForm");

if (loginForm) {

    loginForm.addEventListener("submit", async function (e) {

        e.preventDefault();

        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value;

        const loginBtn = document.getElementById("loginBtn");

        loginBtn.disabled = true;
        loginBtn.innerText = "Logging in...";

        try {

            const response = await fetch(`${API_BASE}/login`, {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    email,
                    password
                })

            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || "Login failed");
            }

            localStorage.setItem("token", data.token);
            localStorage.setItem("user", JSON.stringify(data.user));

            showMessage(
                "Login successful! Redirecting...",
                "success"
            );

            setTimeout(() => {
                window.location.href = "dashboard.html";
            }, 1000);

        } catch (error) {

            showMessage(error.message, "danger");

        } finally {

            loginBtn.disabled = false;
            loginBtn.innerHTML = 'Login <i class="bi bi-arrow-right"></i>';

        }

    });

}