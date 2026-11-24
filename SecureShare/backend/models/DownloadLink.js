const mongoose = require("mongoose");

const downloadLinkSchema = new mongoose.Schema({


file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "File",
    required: true
},

createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
},

tokenHash: {
    type: String,
    required: true,
    unique: true
},

expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }
}

   


}, { timestamps: true });

module.exports = mongoose.model("DownloadLink", downloadLinkSchema);
