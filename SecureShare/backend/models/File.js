const mongoose = require("mongoose");

const fileSchema = new mongoose.Schema(
{
originalName: {
type: String,
required: true
},


    storedName: {
        type: String,
        required: true,
        unique: true
    },

    mimeType: {
        type: String,
        required: true
    },

    size: {
        type: Number,
        required: true
    },

    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true
    },

    encrypted: {
        type: Boolean,
        default: true
    }
},
{
    timestamps: true
}


);

module.exports = mongoose.model("File", fileSchema);
