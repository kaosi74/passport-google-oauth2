import mongoose from "mongoose";
const { Schema } = mongoose;

const UserSchema = new Schema({
    fName: String,
    lName: String,
    email: String,
    psw: String,
})

export const User = mongoose.model('User', UserSchema);
