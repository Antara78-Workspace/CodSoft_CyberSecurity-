const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");

const File = require("../models/File");
const { encryptBuffer, decryptBuffer } = require("../services/encryptionService");

const UPLOAD_DIR = path.join(__dirname, "..", "uploads");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
storage: multer.memoryStorage(),
limits: {
fileSize: 10 * 1024 * 1024
}
});

// UPLOAD FILE
const uploadFile = async (req, res) => {
let filePath;


try {
    if (!req.file) {
        return res.status(400).json({
            message: "Please select a file to upload."
        });
    }

    const encryptedBuffer = encryptBuffer(req.file.buffer);
    const storedName = crypto.randomUUID();

    filePath = path.join(UPLOAD_DIR, storedName);

    fs.writeFileSync(filePath, encryptedBuffer);

    const fileDocument = await File.create({
        originalName: path.basename(req.file.originalname),
        storedName,
        mimeType: req.file.mimetype || "application/octet-stream",
        size: req.file.size,
        owner: req.user.userId,
        encrypted: true
    });

    return res.status(201).json({
        message: "File uploaded and encrypted successfully.",
        file: {
            id: fileDocument._id,
            name: fileDocument.originalName,
            size: fileDocument.size,
            uploadedAt: fileDocument.createdAt
        }
    });
} catch (error) {
    if (filePath && fs.existsSync(filePath)) {
        try {
            fs.unlinkSync(filePath);
        } catch (cleanupError) {
            console.error("Cleanup error:", cleanupError.message);
        }
    }

    console.error("Upload error:", error.message);

    return res.status(500).json({
        message: "File upload failed."
    });
}


};

// GET MY FILES
const getMyFiles = async (req, res) => {
try {
const files = await File.find({
owner: req.user.userId
}).sort({ createdAt: -1 });


    return res.status(200).json({
        count: files.length,
        files: files.map((file) => ({
            id: file._id,
            name: file.originalName,
            mimeType: file.mimeType,
            size: file.size,
            encrypted: file.encrypted,
            uploadedAt: file.createdAt
        }))
    });
} catch (error) {
    console.error("Get files error:", error.message);

    return res.status(500).json({
        message: "Could not retrieve your files."
    });
}


};

// DOWNLOAD FILE
const downloadFile = async (req, res) => {
try {
const file = await File.findOne({
_id: req.params.id,
owner: req.user.userId
});


    if (!file) {
        return res.status(404).json({
            message: "File not found."
        });
    }

    const filePath = path.join(UPLOAD_DIR, file.storedName);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({
            message: "Stored file is unavailable."
        });
    }

    const encryptedBuffer = fs.readFileSync(filePath);
    const decryptedBuffer = decryptBuffer(encryptedBuffer);

    res.setHeader("Content-Type", "application/octet-stream");

    res.setHeader(
        "Content-Disposition",
        'attachment; filename="download"; filename*=UTF-8\'\'' +
        encodeURIComponent(file.originalName)
    );

    res.setHeader("Cache-Control", "no-store");

    return res.status(200).send(decryptedBuffer);
} catch (error) {
    console.error("Download error:", error.message);

    if (error.name === "CastError") {
        return res.status(400).json({
            message: "Invalid file ID."
        });
    }

    return res.status(500).json({
        message: "File download failed."
    });
}


};

// DELETE FILE
const deleteFile = async (req, res) => {
try {
const file = await File.findOne({
_id: req.params.id,
owner: req.user.userId
});


    if (!file) {
        return res.status(404).json({
            message: "File not found."
        });
    }

    const filePath = path.join(UPLOAD_DIR, file.storedName);

    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
    }

    await File.deleteOne({ _id: file._id });

    return res.status(200).json({
        message: "File deleted successfully."
    });
} catch (error) {
    console.error("Delete error:", error.message);

    if (error.name === "CastError") {
        return res.status(400).json({
            message: "Invalid file ID."
        });
    }

    return res.status(500).json({
        message: "File deletion failed."
    });
}


};

// EXPORT FUNCTIONS
module.exports = {
upload,
uploadFile,
getMyFiles,
downloadFile,
deleteFile
};
