const fs = require("fs");
const crypto = require("crypto");
const readline = require("readline");

const file = "./data/users.json";
const users = JSON.parse(fs.readFileSync(file, "utf8"));

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question("New OWNER password: ", ownerPassword => {
  rl.question("New ADMIN password: ", adminPassword => {

    for (const u of users) {
      if (u.role === "owner") {
        const hp = hashPassword(ownerPassword);
        u.salt = hp.salt;
        u.passwordHash = hp.hash;
      }

      if (u.role === "admin") {
        const hp = hashPassword(adminPassword);
        u.salt = hp.salt;
        u.passwordHash = hp.hash;
      }
    }

    fs.writeFileSync(file, JSON.stringify(users, null, 2));
    console.log("Owner and Admin passwords reset successfully.");
    rl.close();
  });
});
