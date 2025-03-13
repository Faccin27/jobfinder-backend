import app from "./app";

const start = async () => {
  try {
    await app.listen({ port: 3050});
    console.log("🚀 Server is running on http://localhost:3000");
  } catch (err) {
    console.error("❌ Error starting server:", err);
    process.exit(1);
  }
};

start();
