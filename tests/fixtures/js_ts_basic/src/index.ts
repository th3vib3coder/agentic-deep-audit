import { helper } from "./util";
import lodash from "lodash";

export { helper } from "./util";

if (process.env.RUNTIME_PLUGIN) {
  const pluginName = process.env.RUNTIME_PLUGIN;
  require(pluginName);
}

module.exports = { helper, lodash };
