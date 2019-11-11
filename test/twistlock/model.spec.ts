"use strict";

import { suite, test, describe } from "mocha";
import { expect, assert } from "chai";
import * as chai from "chai";
import * as sinon from "sinon";
chai.should();
chai.use(require("sinon-chai"));
chai.use(require("chai-as-promised"));
chai.use(require("chai-things"));

import { TwistlockModel } from "../../src/model";
import { Harness } from "@swingletree-oss/harness";


const sandbox = sinon.createSandbox();

describe("Twistlock Model", () => {

  describe("SeverityUtil", () => {
    const checkMap = new Map<TwistlockModel.TwistlockSeverity, Harness.Severity>();

    checkMap.set(TwistlockModel.TwistlockSeverity.LOW, Harness.Severity.INFO);
    checkMap.set(TwistlockModel.TwistlockSeverity.MEDIUM, Harness.Severity.WARNING);
    checkMap.set(TwistlockModel.TwistlockSeverity.HIGH, Harness.Severity.BLOCKER);
    checkMap.set(TwistlockModel.TwistlockSeverity.CRITICAL, Harness.Severity.BLOCKER);

    checkMap.forEach((value, key) => {
      it(`should correctly convert Twistlock Severity "${key}" to Swingletree Severity "${value}"`, () => {
        expect(TwistlockModel.SeverityUtil.convertToSwingletreeSeverity(key)).to.equal(value);
      });
    });
  });

  it("should retrieve Twistlock severity from riskFactors map", () => {
    [
      TwistlockModel.TwistlockSeverity.LOW,
      TwistlockModel.TwistlockSeverity.MEDIUM,
      TwistlockModel.TwistlockSeverity.HIGH,
      TwistlockModel.TwistlockSeverity.CRITICAL
    ].forEach(severity => {
      const riskFactors = {};
      riskFactors[severity + " SeVerItY"] = {};

      expect(TwistlockModel.SeverityUtil.getTwistlockSeverityFromRiskFactor(riskFactors)).to.equal(severity);
    });
  });

});