import mongoose from "mongoose";

const connectdb = async () => {
  try {
    await mongoose.connect(`${process.env.MONGODB_URL}/skillswap_project`);
    console.log("✅ MongoDB Connected");
  } catch (error) {
    console.error("❌ MongoDB Connection Failed:", error);
    process.exit(1);
  }
};

export default connectdb;
