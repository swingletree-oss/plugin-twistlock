import { inject, injectable } from "inversify";
import { ConfigurationService, TwistlockConfig } from "./configuration";
import { TwistlockModel } from "./model";
import { Harness, log } from "@swingletree-oss/harness";
import ScottyClient from "@swingletree-oss/scotty-client";
import { TemplateEngine, Templates } from "./template/template-engine";

@injectable()
class TwistlockStatusEmitter {
  private readonly templateEngine: TemplateEngine;
  private readonly context: string;
  private readonly scottyClient: ScottyClient;

  constructor(
    @inject(ConfigurationService) configurationService: ConfigurationService,
    @inject(TemplateEngine) templateEngine: TemplateEngine,
  ) {
    this.templateEngine = templateEngine;
    this.context = configurationService.get(TwistlockConfig.CONTEXT);
    this.scottyClient = new ScottyClient(configurationService.get(TwistlockConfig.SCOTTY_URL));
  }

  private getAnnotations(issueReport: TwistlockModel.util.FindingReport): Harness.Annotation[] {
    const annotations: Harness.ProjectAnnotation[] = [];

    issueReport.complianceIssues.forEach(issue => {
      const annotation = new Harness.ProjectAnnotation();
      annotation.title = issue.title;
      annotation.severity = TwistlockModel.SeverityUtil.convertToSwingletreeSeverity(issue.severity);

      annotations.push(annotation);
    });

    issueReport.vulnerabilityIssues.forEach(issue => {
      const severity = TwistlockModel.SeverityUtil.getTwistlockSeverityFromRiskFactor(issue.riskFactors);
      const annotation = new Harness.ProjectAnnotation();
      annotation.title = issue.id;
      annotation.href = issue.link;
      annotation.severity = TwistlockModel.SeverityUtil.convertToSwingletreeSeverity(severity);
      annotation.metadata = {
        vector: issue.vector,
        status: issue.status,
        package: issue.packageName,
        version: issue.packageVersion,
        cvss: issue.cvss
      };

      annotations.push(annotation);
    });

    return annotations;
  }

  private getConclusion(annotations: Harness.Annotation[]): Harness.Conclusion {
    let conclusion = Harness.Conclusion.PASSED;
    const hasBlocker = annotations.find(it => { return it.severity == Harness.Severity.BLOCKER; });

    if (hasBlocker) {
      conclusion = Harness.Conclusion.BLOCKED;
    }

    return conclusion;
  }

  public async sendReport(report: TwistlockModel.Report, source: Harness.ScmSource, uid: string) {

    const repoConfig = await this.scottyClient.getRepositoryConfig(source);
    const config = new TwistlockModel.DefaultRepoConfig(repoConfig.getPluginConfig("twistlock") as any);

    const issueReport = new TwistlockModel.util.FindingReport(
      report,
      config.thresholdCvss,
      config.thresholdCompliance,
      config.whitelist
    );

    const templateData: TwistlockModel.Template = {
      report: report,
      issues: issueReport
    };

    const annotations = this.getAnnotations(issueReport);

    const analysisReport: Harness.AnalysisReport = {
      sender: this.context,
      source: source,
      uuid: uid,
      checkStatus: this.getConclusion(annotations),
      title: `${issueReport.issuesCount()} issues found`,
      annotations: annotations
    };

    analysisReport.markdown =  this.templateEngine.template<TwistlockModel.Template>(
      Templates.TWISTLOCK_SCAN,
      templateData
    );

    try {
      return await this.scottyClient.sendReport(analysisReport);
    } catch (error) {
      log.error("could not send payload to scotty.\n%j", error);
    }
  }
}

export default TwistlockStatusEmitter;