// Node.js test comparing ACTUAL slow-redact vs fast-redact libraries
// Run with: node --test actual-redact-comparison.test.js

const { test } = require('node:test')
const { strict: assert } = require('node:assert')
const fastRedact = require("fast-redact")
const slowRedact = require("./index.js")
  // Test slow-redact directly
  function testSlowRedactDirect(pattern, testData = {}) {
    let matches = []

    try {
      const redactor = slowRedact({
        paths: [pattern],
        censor: (value, path) => {
          if (
            value !== undefined &&
            value !== null &&
            typeof value === "string" &&
            value.includes("secret")
          ) {
            matches.push({
              value: value,
              path: path ? path.join(".") : "unknown",
            })
          }

          return "[REDACTED]"
        },
      })

      redactor(JSON.parse(JSON.stringify(testData)))

      return {
        library: "slow-redact",
        pattern: pattern,
        matches: matches,
        success: true,
        testData: testData,
      }
    } catch (error) {
      return {
        library: "slow-redact",
        pattern: pattern,
        matches: [],
        success: false,
        error: error.message,
        testData: testData,
      }
    }
  }

  // Test fast-redact directly
  function testFastRedactDirect(pattern, testData = {}) {
    let matches = []

    try {
      const redactor = fastRedact({
        paths: [pattern],
        censor: (value, path) => {
          if (
            value !== undefined &&
            value !== null &&
            typeof value === "string" &&
            value.includes("secret")
          ) {
            matches.push({
              value: value,
              path: path ? path.join(".") : "unknown",
            })
          }

          return "[REDACTED]"
        },
      })

      redactor(JSON.parse(JSON.stringify(testData)))

      return {
        library: "fast-redact",
        pattern: pattern,
        matches: matches,
        success: true,
        testData: testData,
      }
    } catch (error) {
      return {
        library: "fast-redact",
        pattern: pattern,
        matches: [],
        success: false,
        error: error.message,
        testData: testData,
      }
    }
  }

test("slow-redact: *.password (2 levels)", () => {
      const result = testSlowRedactDirect("*.password", {
        simple: { password: "secret-2-levels" },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "secret-2-levels")
    })

test("slow-redact: *.*.password (3 levels)", () => {
      const result = testSlowRedactDirect("*.*.password", {
        simple: { password: "secret-2-levels" },
        user: { auth: { password: "secret-3-levels" } },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "secret-3-levels")
    })

test("slow-redact: *.*.*.password (4 levels)", () => {
      const result = testSlowRedactDirect("*.*.*.password", {
        simple: { password: "secret-2-levels" },
        user: { auth: { password: "secret-3-levels" } },
        nested: { deep: { auth: { password: "secret-4-levels" } } },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "secret-4-levels")
    })

test("slow-redact: *.*.*.*.password (5 levels)", () => {
      const result = testSlowRedactDirect("*.*.*.*.password", {
        simple: { password: "secret-2-levels" },
        user: { auth: { password: "secret-3-levels" } },
        nested: { deep: { auth: { password: "secret-4-levels" } } },
        config: {
          user: { auth: { settings: { password: "secret-5-levels" } } },
        },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "secret-5-levels")
    })

test("slow-redact: *.*.*.*.*.password (6 levels)", () => {
      const result = testSlowRedactDirect("*.*.*.*.*.password", {
        simple: { password: "secret-2-levels" },
        user: { auth: { password: "secret-3-levels" } },
        nested: { deep: { auth: { password: "secret-4-levels" } } },
        config: {
          user: { auth: { settings: { password: "secret-5-levels" } } },
        },
        data: {
          reqConfig: {
            data: {
              credentials: {
                settings: {
                  password: "real-secret-6-levels",
                },
              },
            },
          },
        },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "real-secret-6-levels")
    })

test("fast-redact: *.password (2 levels)", () => {
      const result = testFastRedactDirect("*.password", {
        simple: { password: "secret-2-levels" },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "secret-2-levels")
    })

test("fast-redact: *.*.password (3 levels)", () => {
      const result = testFastRedactDirect("*.*.password", {
        simple: { password: "secret-2-levels" },
        user: { auth: { password: "secret-3-levels" } },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "secret-3-levels")
    })

test("fast-redact: *.*.*.password (4 levels)", () => {
      const result = testFastRedactDirect("*.*.*.password", {
        simple: { password: "secret-2-levels" },
        user: { auth: { password: "secret-3-levels" } },
        nested: { deep: { auth: { password: "secret-4-levels" } } },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "secret-4-levels")
    })

test("fast-redact: *.*.*.*.password (5 levels)", () => {
      const result = testFastRedactDirect("*.*.*.*.password", {
        simple: { password: "secret-2-levels" },
        user: { auth: { password: "secret-3-levels" } },
        nested: { deep: { auth: { password: "secret-4-levels" } } },
        config: {
          user: { auth: { settings: { password: "secret-5-levels" } } },
        },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "secret-5-levels")
    })

test("fast-redact: *.*.*.*.*.password (6 levels)", () => {
      const result = testFastRedactDirect("*.*.*.*.*.password", {
        simple: { password: "secret-2-levels" },
        user: { auth: { password: "secret-3-levels" } },
        nested: { deep: { auth: { password: "secret-4-levels" } } },
        config: {
          user: { auth: { settings: { password: "secret-5-levels" } } },
        },
        data: {
          reqConfig: {
            data: {
              credentials: {
                settings: {
                  password: "real-secret-6-levels",
                },
              },
            },
          },
        },
      })

      assert.strictEqual(result.success, true)
      assert.strictEqual(result.matches.length, 1)
      assert.strictEqual(result.matches[0].value, "real-secret-6-levels")
    })
