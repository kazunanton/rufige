const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const src = path.join(root, "deploy");
const dest = path.join(root, "public");

if (!fs.existsSync(src)) {
  console.error("deploy/ not found");
  process.exit(1);
}

fs.rmSync(dest, { recursive: true, force: true });
fs.cpSync(src, dest, { recursive: true });
console.log("Copied deploy/ to public/");
