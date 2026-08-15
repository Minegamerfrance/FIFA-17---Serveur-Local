import "dotenv/config";
import { prisma } from "../src/database/index.ts";

async function main() {
  try {
    console.log("DATABASE_URL=", process.env.DATABASE_URL);
    await prisma.$connect();
    console.log("connected");
    const user = await prisma.user.findFirst({ where: { email: "player@fifa17.local" } });
    console.log("USER=", user);
  } catch (err) {
    console.error("ERR-RAW=", err);
    if (err instanceof Error) {
      console.error("ERR-MESSAGE=", err.message);
      console.error("ERR-STACK=", err.stack);
    }
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error("MAIN-ERR=", err);
  process.exit(1);
});
