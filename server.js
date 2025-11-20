import app from "./src/app.js";

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => console.log(`API running on ${PORT}`));

process.on('unhandledRejection', (err) => {
  console.log('Unhandled Rejection! Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});
