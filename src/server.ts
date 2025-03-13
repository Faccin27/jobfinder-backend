import app from "./app";

const start = async () => {
  try {
    await app.listen({ port: 3535});
    console.log("🚀 Server is running on http://localhost:3535");
  } catch (err) {
    console.error("❌ Error starting server:", err);
    process.exit(1);
  }
};

start();
