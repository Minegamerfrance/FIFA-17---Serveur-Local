import { prisma } from "../database/index.js";
import { log } from "../shared/logger.js";
import { randomUUID } from "node:crypto";

export async function ensureDefaultUser(email = "player@fifa17.local", password = "local") {
  const lookupEmail = typeof email === "string" && email.length ? email : "player@fifa17.local";
  let user = await prisma.user.findFirst({ where: { email: lookupEmail } });
  if (!user) {
    user = await prisma.user.create({
      data: {
        email: lookupEmail,
        password,
        personas: {
          create: {
            name: "LocalPlayer",
            club: { create: { name: "Local FC" } },
          },
        },
      },
      include: { personas: true },
    });
    log("info", "auth", `seeded default user ${lookupEmail}`);
  }
  return user;
}

export async function createSession(personaId: number, ttlMs = 24 * 60 * 60 * 1000) {
  const token = randomUUID();
  return prisma.session.create({
    data: {
      token,
      personaId,
      expiresAt: new Date(Date.now() + ttlMs),
    },
  });
}

export async function findSession(token: string) {
  return prisma.session.findUnique({
    where: { token },
    include: { persona: { include: { user: true, club: true } } },
  });
}
