/**
 * Standalone Origin LSX emulator on 127.0.0.1:4216 (FIFA 17 PC)
 *
 * IMPORTANT: Origin.exe must NOT hold :4216.
 *   netstat -ano | findstr :4216
 *   Stop-Process -Name Origin -Force
 *
 *   npm run start:lsx
 */
import "dotenv/config";
