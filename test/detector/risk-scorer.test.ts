import { expect } from "chai";
import { describe, it } from "mocha";

import { getRiskRating } from "../../src/detector/risk-scorer.ts";

describe("risk scorer", () => {
    it("marks safe-postinstall-test as HIGH", async () => {
        const rating = await getRiskRating("safe-postinstall-test", "0.0.1");

        expect(rating).to.equal("HIGH");
    });
});
