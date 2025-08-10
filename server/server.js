import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import connectdb from "./config/mongodb.js"; // correct extension for ESM
import authRouter from "./routes/authRoutes.js";
import userRoutesr from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 4000;

connectdb();

app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true }));

// api endpoints
app.get('/', (req, res) => res.send("API Working krish"));
app.use('/api/auth', authRouter) // ✅ Correct path
app.use('/api/user', userRoutesr) 


app.listen(port, () => console.log(`Server started on PORT:${port}`));