import app from "./src/app";

const PORT = process.env.PORT || 8000;
const HOST = process.env.HOST || "localhost";

const server = app.listen(PORT, () =>
    console.log(`API running on http://${HOST}:${PORT}`)
);

process.on("unhandledRejection", (err: Error) => {
    console.log("Unhandled Rejection! Shutting down...");
    console.log(err.name, err.message);
    server.close(() => {
        process.exit(1);
    });
});
