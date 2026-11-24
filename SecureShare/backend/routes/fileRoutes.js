const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");

const {
upload,
uploadFile,
getMyFiles,
downloadFile,
deleteFile
} = require("../controllers/fileController");

const {
generateDownloadLink,
downloadUsingLink
} = require("../controllers/downloadLinkController");

// Public temporary download route
router.get("/shared/:token", downloadUsingLink);

// Protected routes
router.use(authMiddleware);

router.post("/upload", upload.single("file"), uploadFile);

router.get("/my", getMyFiles);

router.get("/download/:id", downloadFile);

router.delete("/:id", deleteFile);

// Generate temporary download link
router.post("/generate-link", generateDownloadLink);

module.exports = router;
 