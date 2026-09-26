const fs = require("fs");
process.stdout.write(JSON.stringify(JSON.parse(fs.readFileSync(process.argv[2], "utf8"))));
