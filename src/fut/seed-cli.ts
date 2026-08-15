import { seedPlayers, ensureAccountClub } from "./seed.js";
import { config } from "../config.js";
import { log } from "../shared/logger.js";
import { closeDb } from "./db.js";

seedPlayers();
ensureAccountClub(config.defaultPersonaId, config.defaultNucleusId, config.defaultPersonaName);
log("info", "seed-cli", `database ready at ${config.databasePath}`);
closeDb();
