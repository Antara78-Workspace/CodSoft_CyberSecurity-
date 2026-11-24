
// Generate temporary download link

async function generateTemporaryLink(fileId) {

    const expiry = prompt(
        "Enter link expiry time in minutes (1 to 1440):",
        "10"
    );

    if (expiry === null) {
        return;
    }

    const minutes = Number(expiry);

    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
        alert("Please enter a valid expiry between 1 and 1440 minutes.");
        return;
    }

    try {

        const response = await fetch(`${API_BASE}/generate-link`, {

            method: "POST",

            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`
            },

            body: JSON.stringify({
                fileId: fileId,
                expiresInMinutes: minutes
            })

        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || "Unable to generate link.");
        }

        // Copy generated link
        await navigator.clipboard.writeText(data.downloadUrl);

        alert(
            "Temporary download link generated and copied successfully!\n\n" +
            "Expires at: " + new Date(data.expiresAt).toLocaleString()
        );

    } catch (error) {

        alert(error.message);

    }

}




const API_BASE = "http://localhost:5000/api/files";

const token = localStorage.getItem("token");

const user = JSON.parse(localStorage.getItem("user") || "null");

// Check authentication

if (!token) {
    window.location.href = "login.html";
}

// Elements

const welcomeUser = document.getElementById("welcomeUser");

const totalFilesElement = document.getElementById("totalFiles");
const encryptedFilesElement = document.getElementById("encryptedFiles");
const storageUsedElement = document.getElementById("storageUsed");

const uploadForm = document.getElementById("uploadForm");
const fileInput = document.getElementById("fileInput");
const uploadBtn = document.getElementById("uploadBtn");
const uploadMessage = document.getElementById("uploadMessage");

const filesTableBody = document.getElementById("filesTableBody");

const loadingMessage = document.getElementById("loadingMessage");
const emptyMessage = document.getElementById("emptyMessage");
const fileTableContainer = document.getElementById("fileTableContainer");
const errorMessage = document.getElementById("errorMessage");

const refreshBtn = document.getElementById("refreshBtn");
const logoutBtn = document.getElementById("logoutBtn");

// Display user

if (user) {
    welcomeUser.textContent = `Welcome, ${user.name || user.email || "User"}`;
}

// Logout

logoutBtn.addEventListener("click", () => {

    localStorage.removeItem("token");
    localStorage.removeItem("user");

    window.location.href = "index.html";

});

// Format file size

function formatFileSize(bytes) {

    if (bytes < 1024) {
        return bytes + " B";
    }

    if (bytes < 1024 * 1024) {
        return (bytes / 1024).toFixed(2) + " KB";
    }

    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

// Display storage size

function formatStorage(bytes) {

    if (bytes < 1024 * 1024) {
        return (bytes / 1024).toFixed(2) + " KB";
    }

    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

// Load files

async function loadFiles() {

    loadingMessage.hidden = false;
    emptyMessage.hidden = true;
    fileTableContainer.hidden = true;
    errorMessage.hidden = true;

    try {

        const response = await fetch(`${API_BASE}/my`, {
            method: "GET",
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        const data = await response.json();

        if (!response.ok) {

            if (response.status === 401) {
                localStorage.removeItem("token");
                localStorage.removeItem("user");
                window.location.href = "login.html";
                return;
            }

            throw new Error(data.message || "Unable to load files.");

        }

        const files = data.files || [];

        filesTableBody.replaceChildren();

        totalFilesElement.textContent = files.length;

        const encryptedCount = files.filter(file => file.encrypted).length;

        encryptedFilesElement.textContent = encryptedCount;

        const totalStorage = files.reduce(
            (total, file) => total + (file.size || 0),
            0
        );

        storageUsedElement.textContent = formatStorage(totalStorage);

        loadingMessage.hidden = true;

        if (files.length === 0) {
            emptyMessage.hidden = false;
            return;
        }

        fileTableContainer.hidden = false;

        files.forEach(file => {

            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const icon = document.createElement("i");

            icon.className = "bi bi-file-earmark file-icon";

            const name = document.createElement("span");
            name.className = "file-name";
            name.textContent = file.originalName || file.name || "Unnamed file";

            nameCell.append(icon, name);

            const sizeCell = document.createElement("td");
            sizeCell.textContent = formatFileSize(file.size || 0);

            const encryptionCell = document.createElement("td");

            const badge = document.createElement("span");
            badge.className = file.encrypted ? "encrypted-badge" : "text-warning";
            badge.textContent = file.encrypted ? "Encrypted" : "Not Encrypted";

            encryptionCell.appendChild(badge);

            const dateCell = document.createElement("td");

            const uploadedDate = file.createdAt || file.uploadedAt;

            dateCell.textContent = uploadedDate
                ? new Date(uploadedDate).toLocaleDateString()
                : "N/A";

            const actionCell = document.createElement("td");

            const downloadButton = document.createElement("button");
            downloadButton.className = "action-btn download-btn";
            downloadButton.innerHTML = '<i class="bi bi-download"></i>';
            downloadButton.title = "Download file";

            downloadButton.addEventListener("click", () => {
                downloadFile(file._id || file.id, file.originalName || file.name);
            });

            const deleteButton = document.createElement("button");
            deleteButton.className = "action-btn delete-btn";
            deleteButton.innerHTML = '<i class="bi bi-trash"></i>';
            deleteButton.title = "Delete file";

            deleteButton.addEventListener("click", () => {
                deleteFile(file._id || file.id);
            });

            // Generate temporary link button
const shareButton = document.createElement("button");

shareButton.className = "action-btn share-btn";
shareButton.innerHTML = '<i class="bi bi-share"></i>';
shareButton.title = "Generate temporary download link";

shareButton.addEventListener("click", () => {
    generateTemporaryLink(file._id || file.id);
});

actionCell.append(downloadButton, shareButton, deleteButton);

            row.append(
                nameCell,
                sizeCell,
                encryptionCell,
                dateCell,
                actionCell
            );

            filesTableBody.appendChild(row);

        });

    } catch (error) {

        loadingMessage.hidden = true;

        errorMessage.textContent = error.message;
        errorMessage.hidden = false;

    }

}

// Upload file

uploadForm.addEventListener("submit", async (event) => {

    event.preventDefault();

    const file = fileInput.files[0];

    if (!file) {
        showUploadMessage("Please select a file.", "danger");
        return;
    }

    if (file.size > 10 * 1024 * 1024) {
        showUploadMessage("File size must be less than 10 MB.", "danger");
        return;
    }

    const formData = new FormData();

    formData.append("file", file);

    uploadBtn.disabled = true;
    uploadBtn.textContent = "Uploading...";

    try {

        const response = await fetch(`${API_BASE}/upload`, {

            method: "POST",

            headers: {
                Authorization: `Bearer ${token}`
            },

            body: formData

        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || "File upload failed.");
        }

        showUploadMessage("File uploaded and encrypted successfully!", "success");

        uploadForm.reset();

        await loadFiles();

    } catch (error) {

        showUploadMessage(error.message, "danger");

    } finally {

        uploadBtn.disabled = false;

        uploadBtn.innerHTML = '<i class="bi bi-upload"></i> Upload File';

    }

});

// Upload message

function showUploadMessage(message, type) {

    uploadMessage.className = `alert alert-${type} mt-3`;
    uploadMessage.textContent = message;

}

// Download and decrypt file

async function downloadFile(fileId, fileName) {

    try {

        const response = await fetch(`${API_BASE}/download/${fileId}`, {

            method: "GET",

            headers: {
                Authorization: `Bearer ${token}`
            }

        });

        if (!response.ok) {

            const data = await response.json();
            throw new Error(data.message || "Download failed.");

        }

        const blob = await response.blob();

        const objectURL = window.URL.createObjectURL(blob);

        const link = document.createElement("a");

        link.href = objectURL;
        link.download = fileName || "downloaded-file";

        document.body.appendChild(link);

        link.click();

        link.remove();

        window.URL.revokeObjectURL(objectURL);

    } catch (error) {

        alert(error.message);

    }

}

// Delete file

async function deleteFile(fileId) {

    const confirmed = confirm("Are you sure you want to delete this file?");

    if (!confirmed) {
        return;
    }

    try {

        const response = await fetch(`${API_BASE}/${fileId}`, {

            method: "DELETE",

            headers: {
                Authorization: `Bearer ${token}`
            }

        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || "Unable to delete file.");
        }

        alert("File deleted successfully.");

        await loadFiles();

    } catch (error) {

        alert(error.message);

    }

}

// Refresh

refreshBtn.addEventListener("click", loadFiles);

// Initial load

loadFiles();