import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: String,
  name: String,
  email: String,
  password: String,
  // profilepic: {
  //   type: String,
  //   default: ""
  // }
}, { timestamps: true });

const userModel = mongoose.model('user', userSchema);
export default userModel;
