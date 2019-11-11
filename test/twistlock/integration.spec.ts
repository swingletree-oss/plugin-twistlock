"use strict";

import { suite, test, describe } from "mocha";
import { expect, assert } from "chai";
import * as chai from "chai";
import * as sinon from "sinon";
chai.use(require("sinon-chai"));
chai.use(require("chai-as-promised"));

import TwistlockStatusEmitter from "../../src/status-emitter";
import { ConfigurationServiceMock, TemplateEngineMock, ScottyClientMock } from "../mock-classes";
import { Harness } from "@swingletree-oss/harness";
import { TwistlockModel } from "../../src/model";
import ScottyClient from "@swingletree-oss/scotty-client";

const sandbox = sinon.createSandbox();

function mockResult(file: string): any {
  return JSON.parse(JSON.stringify(require(file)));
}

describe("Twistlock", () => {

  let uut: TwistlockStatusEmitter;
  let scottyClient: ScottyClient;

  beforeEach(() => {
    uut = new TwistlockStatusEmitter(
      new ConfigurationServiceMock(),
      new TemplateEngineMock()
    );

    scottyClient = new ScottyClientMock();
    (uut as any).scottyClient = scottyClient;
  });

  describe("status emitter", async () => {
    it("should mark check run with action required on dirty report", async () => {

      const source = new Harness.GithubSource();
      source.owner = "org";
      source.repo = "repo";

      const tlData = mockResult("../mock/twistlock-report-all.json") as TwistlockModel.Report;

      await uut.sendReport(tlData, source);

      sinon.assert.calledOnce(scottyClient.sendReport as any);

      sinon.assert.calledWith(scottyClient.sendReport as any, sinon.match.hasNested("checkStatus", sinon.match(Harness.Conclusion.BLOCKED)));
    });

    it("should mark check run with success on findings lower HIGH", async () => {

      const source = new Harness.GithubSource();
      source.owner = "org";
      source.repo = "repo";

      const tlData = mockResult("../mock/twistlock-report-clean.json");

      tlData.results[0].vulnerabilities = [
        {
          "id": "CVE-2019-3857",
          "status": "fixed in 1.4.3-12.el7_6.2",
          "cvss": 8.8,
          "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
          "description": "An integer overflow flaw which could lead to an out of bounds write was discovered in libssh2 before 1.8.1 in the way SSH_MSG_CHANNEL_REQUEST packets with an exit signal are parsed. A remote attacker who compromises a SSH server may be able to execute code on the client system when a user connects to the server.",
          "severity": TwistlockModel.VulnerabilitySeverity.MEDIUM,
          "packageName": "libssh2",
          "packageVersion": "1.4.3-12.el7",
          "link": "https://access.redhat.com/security/cve/CVE-2019-3857",
          "riskFactors": {
            "Attack vector: network": {},
            "Has fix": {},
            "Medium severity": {},
            "Recent vulnerability": {}
          }
        }
      ];

      await uut.sendReport(tlData, source);

      sinon.assert.calledOnce(scottyClient.sendReport as any);

      sinon.assert.calledWith(scottyClient.sendReport as any, sinon.match.hasNested("checkStatus", sinon.match(Harness.Conclusion.PASSED)));
      sinon.assert.calledWith(scottyClient.sendReport as any, sinon.match.hasNested("annotations", sinon.match(value => {
        return value.length == 1 &&
          value[0].title == "CVE-2019-3857";
      })));
    });

    it("should mark check run with failure on findings equal HIGH", async () => {

      const source = new Harness.GithubSource();
      source.owner = "org";
      source.repo = "repo";

      const tlData = mockResult("../mock/twistlock-report-clean.json");

      tlData.results[0].vulnerabilities = [
        {
          "id": "CVE-2019-3857",
          "status": "fixed in 1.4.3-12.el7_6.2",
          "cvss": 8.8,
          "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
          "description": "An integer overflow flaw which could lead to an out of bounds write was discovered in libssh2 before 1.8.1 in the way SSH_MSG_CHANNEL_REQUEST packets with an exit signal are parsed. A remote attacker who compromises a SSH server may be able to execute code on the client system when a user connects to the server.",
          "severity": TwistlockModel.VulnerabilitySeverity.MEDIUM,
          "packageName": "libssh2",
          "packageVersion": "1.4.3-12.el7",
          "link": "https://access.redhat.com/security/cve/CVE-2019-3857",
          "riskFactors": {
            "Attack vector: network": {},
            "Has fix": {},
            "High severity": {},
            "Recent vulnerability": {}
          }
        }
      ];

      await uut.sendReport(tlData, source);

      sinon.assert.calledOnce(scottyClient.sendReport as any);

      sinon.assert.calledWith(scottyClient.sendReport as any, sinon.match.hasNested("checkStatus", sinon.match(Harness.Conclusion.BLOCKED)));
      sinon.assert.calledWith(scottyClient.sendReport as any, sinon.match.hasNested("annotations", sinon.match(value => {
        return value.length == 1 &&
          value[0].title == "CVE-2019-3857";
      })));
    });

    it("should mark check run with success on clean report", async () => {

      const source = new Harness.GithubSource();
      source.owner = "org";
      source.repo = "repo";

      const tlData = mockResult("../mock/twistlock-report-clean.json");

      await uut.sendReport(tlData, source);

      sinon.assert.calledOnce(scottyClient.sendReport as any);

      sinon.assert.calledWith(scottyClient.sendReport as any, sinon.match.hasNested("checkStatus", sinon.match(Harness.Conclusion.PASSED)));
    });
  });

});
