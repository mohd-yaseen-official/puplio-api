import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.js";
import dogRoutes from "./routes/dogProfiles.js";
import routineRoutes from "./routes/routines.js";
import activityRoutes from "./routes/activityLogs.js";
import chatRoutes from "./routes/aiChat.js";

const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.json({ message: "Welcome to Puplio" });
});

app.use('/auth', authRoutes);
app.use("/dogs", dogRoutes);
app.use("/routines", routineRoutes)
app.use("/activities", activityRoutes)
app.use("/chats/", chatRoutes)

export default app;