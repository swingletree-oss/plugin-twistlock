"use strict";

import { Request, Response, Router } from "express";
import { inject, injectable } from "inversify";
import { ConfigurationService, TwistlockConfig } from "./configuration";
import { TwistlockModel } from "./model";
import { log, Comms, Harness } from "@swingletree-oss/harness";
import { BadRequestError } from "@swingletree-oss/harness/dist/comms";
import TwistlockStatusEmitter from "./status-emitter";

/** Provides a Webhook for Sonar
 */
@injectable()
class TwistlockWebhook {
  private configurationService: ConfigurationService;
  private readonly statusEmitter: TwistlockStatusEmitter;

  constructor(
    @inject(ConfigurationService) configurationService: ConfigurationService,
    @inject(TwistlockStatusEmitter) statusEmitter: TwistlockStatusEmitter
  ) {
    this.configurationService = configurationService;
    this.statusEmitter = statusEmitter;
  }

  private isWebhookEventRelevant(event: TwistlockModel.Report) {
    return event.results && event.results.length > 0;
  }

  public getRouter(): Router {
    const router = Router();
    router.post("/", this.webhook.bind(this));
    return router;
  }

  public webhook = async (req: Request, res: Response) => {
    log.debug("received Twistlock webhook event");

    const message: Comms.Gate.PluginReportProcessRequest<TwistlockModel.Report> = req.body;

    if (this.configurationService.getBoolean(TwistlockConfig.LOG_WEBHOOK_EVENTS)) {
      log.debug(JSON.stringify(req.body));
    }

    const reportData: TwistlockModel.Report = message.data.report;

    if (!message.meta || !message.meta.source) {
      res.status(400).send(
        new Comms.Message.ErrorMessage(
          new BadRequestError("malformed source object in request metadata.")
        )
      );
      return;
    }

    const source = new Harness.GithubSource(message.meta.source as Harness.GithubSource);

    if (!Harness.GithubSource.isDataComplete(source)) {
      res.status(400).send(
        new Comms.Message.ErrorMessage(
          new BadRequestError("missing source coordinates in request metadata.")
        )
      );
      return;
    }

    if (this.isWebhookEventRelevant(reportData)) {
      log.debug("sending report to Scotty...");
      try {
        await this.statusEmitter.sendReport(reportData, source, message.meta.buildUuid);
      } catch (err) {
        log.warn("failed sending analysis report to Scotty. %j", err);
      }
    } else {
      log.debug("twistlock webhook data did not contain a report. This event will be ignored.");
      res.status(400).send(
        new Comms.Message.ErrorMessage(
          new BadRequestError("twistlock webhook data did not contain a report. This event will be ignored.")
        )
      );
      return;
    }

    res.status(204).send();
  }
}

export default TwistlockWebhook;