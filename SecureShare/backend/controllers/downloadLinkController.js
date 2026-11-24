const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const File = require("../models/File");
const DownloadLink = require("../models/DownloadLink");

const { decryptBuffer } = require("../services/encryptionService");

// Generate temporary download link
const generateDownloadLink = async (req, res) => {

    try {

        const { fileId, expiresInMinutes } = req.body;

        if (!fileId) {
            return res.status(400).json({
                message: "File ID is required."
            });
        }

        const minutes = Number(expiresInMinutes || 10);

        if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
            return res.status(400).json({
                message: "Expiry must be between 1 and 1440 minutes."
            });
        }

        // Check file ownership
        const file = await File.findOne({
            _id: fileId,
            owner: req.user.userId
        });

        if (!file) {
            return res.status(404).json({
                message: "File not found."
            });
        }

        // Generate a secure random token
        const token = crypto.randomBytes(32).toString("hex");

        // Store only the token hash in MongoDB
        const tokenHash = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        const expiresAt = new Date(
            Date.now() + minutes * 60 * 1000
        );

        await DownloadLink.create({
            file: file._id,
            createdBy: req.user.userId,
            tokenHash,
            expiresAt
        });

        const downloadUrl =
            `${req.protocol}://${req.get("host")}/api/files/shared/${token}`;

        return res.status(201).json({
            message: "Temporary download link generated successfully.",
            downloadUrl,
            expiresAt,
            expiresInMinutes: minutes
        });

    } catch (error) {

        console.error("Generate download link error:", error);

        return res.status(500).json({
            message: "Unable to generate download link."
        });

    }

};


// Download using temporary link
const downloadUsingLink = async (req, res) => {

    try {

        const { token } = req.params;

        // Hash received token
        const tokenHash = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        // Find matching link
        const downloadLink = await DownloadLink.findOne({
            tokenHash,
            expiresAt: { $gt: new Date() }
        }).populate("file");

        if (!downloadLink || !downloadLink.file) {
            return res.status(410).json({
                message: "This download link is invalid or has expired."
            });
        }

        const file = downloadLink.file;

        const filePath = path.join(
            __dirname,
            "../uploads",
            file.storedName
        );

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({
                message: "Stored file not found."
            });
        }

        // Read encrypted file
        const encryptedData = fs.readFileSync(filePath);

        // Decrypt file
        const decryptedData = decryptBuffer(encryptedData);

        // Send original file
        const safeName = path.basename(file.originalName)
            .replace(/["\r\n]/g, "_");

        res.setHeader(
            "Content-Type",
            file.mimeType || "application/octet-stream"
        );

        res.setHeader(
            "Content-Disposition",
            `attachment; filename="${safeName}"`
        );

        return res.send(decryptedData);

    } catch (error) {

        console.error("Temporary download error:", error);

        return res.status(500).json({
            message: "Unable to download file."
        });

    }

};


module.exports = {
    generateDownloadLink,
    downloadUsingLink
};