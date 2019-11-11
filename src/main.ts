import container from "./ioc-config";
import { ConfigurationService } from "./configuration";
import TwistlockWebhook from "./webhook";
import TwistlockStatusEmitter from "./status-emitter";
import { TwistlockModel } from "./model";
import { TemplateEngine } from "./template/template-engine";
import { log } from "@swingletree-oss/harness";
import { WebServer } from "./webserver";

require("source-map-support").install();

process.on("unhandledRejection", error => {
  // Will print "unhandledRejection err is not defined"
  console.log("unhandledRejection ", error);
});

export class TwistlockPlugin {

  constructor() {
  }

  public run(): void {
    log.info("Starting up Twistlock Plugin...");
    const webserver = container.get<WebServer>(WebServer);

    // initialize Emitters
    container.get<TwistlockStatusEmitter>(TwistlockStatusEmitter);

    // add webhook endpoint
    webserver.addRouter("/report", container.get<TwistlockWebhook>(TwistlockWebhook).getRouter());

    // add template filter for severity icons
    container.get<TemplateEngine>(TemplateEngine).addFilter("twistlockVulnSeverity", TwistlockPlugin.twistlockVulnerabilitySeverityFilter);
  }

  public static twistlockVulnerabilitySeverityFilter(type: TwistlockModel.VulnerabilitySeverity | string) {
    let result = type;

    switch (type) {
      case TwistlockModel.VulnerabilitySeverity.CRITICAL:		result = ":bangbang:"; break;
      case TwistlockModel.VulnerabilitySeverity.HIGH: 			result = ":exclamation:"; break;
      case TwistlockModel.VulnerabilitySeverity.IMPORTANT: 	result = ":red_circle:"; break;
      case TwistlockModel.VulnerabilitySeverity.MODERATE: 	result = ":small_red_triangle:"; break;
      case TwistlockModel.VulnerabilitySeverity.MEDIUM: 		result = ":small_red_triangle_down:"; break;
      case TwistlockModel.VulnerabilitySeverity.LOW: 				result = ":small_orange_diamond:"; break;
    }

    return result;
  }

}

new TwistlockPlugin().run();
