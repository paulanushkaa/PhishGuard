// PhishGuard v5.0 - ML inference engine.
//
// Loads the REAL trained model exported from training/train_model.py or
// training/train_model_gb.py (model/model.json, flat parallel-array tree
// encoding) and runs inference by walking each tree exactly as scikit-learn
// would, then applies the SAME Platt-scaling calibration fit on the
// validation split (model/metadata.json) to produce a calibrated probability
// alongside the raw one. If the model or its metadata fail to load/validate,
// ML inference is marked UNAVAILABLE - this module never falls back to a
// random or hard-coded probability.
//
// Two model formats are supported (model.json's own "format" field decides
// which at load time - never assumed from a filename):
//   "phishguard-rf-flat-v1" - RandomForestClassifier. Each tree's leaves
//     store a 0-1 probability ("p"); the forest's prediction is the mean
//     across all trees.
//   "phishguard-gb-flat-v1" - GradientBoostingClassifier (real gradient-
//     boosted trees, same algorithm family as XGBoost; used because the
//     xgboost package could not be installed in the training environment -
//     see training/README.md "Model algorithm"). Each tree's leaves store a
//     raw, unbounded additive value ("v"); the prediction is
//     sigmoid(init_raw_score + learning_rate * sum(tree values)).
//
// CRITICAL SAFETY NOTE: a high ML probability (raw or calibrated) is
// evidence, not proof, and by itself is structurally incapable of producing
// a HIGH_RISK verdict - see js/riskEngine.js's weight caps and corroboration
// policy. This module only ever reports a probability; it never decides a
// verdict.

import { FEATURE_NAMES, extractFeatureVector } from "./featureExtractor.js";

let _modelPromise = null;

async function loadJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
  return res.json();
}

function getModelUrl(path) {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL) {
    return chrome.runtime.getURL(path);
  }
  return path;
}

const SUPPORTED_FORMATS = new Set(["phishguard-rf-flat-v1", "phishguard-gb-flat-v1"]);

function validateModel(model) {
  if (!model || !SUPPORTED_FORMATS.has(model.format)) return false;
  if (!Array.isArray(model.trees) || model.trees.length === 0) return false;
  if (!Array.isArray(model.feature_names)) return false;
  if (model.feature_names.length !== FEATURE_NAMES.length) return false;
  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    if (model.feature_names[i] !== FEATURE_NAMES[i]) return false;
  }
  if (model.format === "phishguard-gb-flat-v1") {
    if (typeof model.learning_rate !== "number" || typeof model.init_raw_score !== "number") return false;
  }
  return true;
}

function validateCalibration(metadata) {
  const cal = metadata && metadata.calibration;
  return !!(cal && cal.method === "platt_sigmoid" && typeof cal.w === "number" && typeof cal.b === "number");
}

/**
 * Loads and validates the model + metadata exactly once (memoized). Returns
 * { available: true, model, metadata, calibration } or
 * { available: false, reason }. NEVER throws.
 */
export async function loadModel() {
  if (!_modelPromise) {
    _modelPromise = (async () => {
      try {
        const model = await loadJson(getModelUrl("model/model.json"));
        if (!validateModel(model)) {
          return { available: false, reason: "Model failed schema/feature-order validation" };
        }
        let metadata = null;
        try {
          metadata = await loadJson(getModelUrl("model/metadata.json"));
        } catch (e) {
          metadata = null;
        }
        const calibrationOk = validateCalibration(metadata);
        return {
          available: true,
          model,
          metadata,
          calibration: calibrationOk ? metadata.calibration : null,
        };
      } catch (e) {
        return { available: false, reason: `Model file could not be loaded: ${e.message}` };
      }
    })();
  }
  return _modelPromise;
}

function walkTree(tree, x, leafField, corruptFallback) {
  let node = 0;
  let steps = 0;
  const maxSteps = tree.f.length + 5;
  while (tree.f[node] !== -2) {
    const fi = tree.f[node];
    if (x[fi] <= tree.t[node]) node = tree.l[node];
    else node = tree.r[node];
    steps++;
    if (steps > maxSteps) return corruptFallback; // corrupt tree guard, neutral fallback
  }
  return tree[leafField][node];
}

function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}

function predictProbaFromModel(model, featureVector) {
  const trees = model.trees;
  if (model.format === "phishguard-gb-flat-v1") {
    // Boosted trees: raw_score = init + learning_rate * sum(leaf values).
    // Neutral fallback for a corrupt tree is 0 (no additive contribution),
    // not 0.5 - these leaves are unbounded raw scores, not probabilities.
    let rawScore = model.init_raw_score;
    for (let i = 0; i < trees.length; i++) {
      rawScore += model.learning_rate * walkTree(trees[i], featureVector, "v", 0);
    }
    return sigmoid(rawScore);
  }
  // RandomForest: mean of each tree's leaf probability across the forest.
  let sum = 0;
  for (let i = 0; i < trees.length; i++) sum += walkTree(trees[i], featureVector, "p", 0.5);
  return sum / trees.length;
}

function applyPlatt(rawProba, w, b) {
  return 1 / (1 + Math.exp(-(w * rawProba + b)));
}

/**
 * Runs ML inference for a URL. Returns:
 *  { available: true, rawProbability, calibratedProbability, calibrationApplied, featureVector, modelVersion }
 *  { available: false, reason: string }
 * Never returns a random or fabricated probability. If calibration params
 * are missing/invalid, calibratedProbability falls back to rawProbability
 * and calibrationApplied is false (never silently invented).
 *
 * RANK 7 (performance): `precomputedFeatures`, if provided, must be the
 * exact object extractFeatures(rawUrl) would itself return for this SAME
 * rawUrl (e.g. background.js's own per-navigation facts cache, which is
 * populated by calling that identical function on that identical URL
 * string) - extractFeatures() is a pure function of its input, so reusing
 * an already-computed result for the same URL is mathematically identical
 * to computing it again, just without paying for it twice. This parameter
 * is OPTIONAL and purely additive: every existing call site (every
 * regression test, any future caller) that omits it takes the exact same
 * `await extractFeatureVector(rawUrl)` path this function has always used -
 * nothing about the model, its feature order, its preprocessing, or its
 * output changes. No new function reads this value except the simple
 * `FEATURE_NAMES.map(...)` lookup below, which produces byte-for-byte the
 * same array extractFeatureVector() itself builds from the same object
 * (extractFeatureVector is `FEATURE_NAMES.map((name) => feats[name])` -
 * identical logic, inlined here rather than imported, so this file adds a
 * fast path without importing or modifying extractFeatureVector itself).
 */
export async function predictUrl(rawUrl, precomputedFeatures) {
  const loaded = await loadModel();
  if (!loaded.available) {
    return { available: false, reason: loaded.reason };
  }
  let featureVector;
  try {
    featureVector = precomputedFeatures
      ? FEATURE_NAMES.map((name) => precomputedFeatures[name])
      : await extractFeatureVector(rawUrl);
  } catch (e) {
    return { available: false, reason: `Feature extraction failed: ${e.message}` };
  }
  if (!Array.isArray(featureVector) || featureVector.length !== FEATURE_NAMES.length) {
    return { available: false, reason: "Feature vector shape mismatch - ML inference skipped for safety" };
  }
  if (featureVector.some((v) => v === null || v === undefined || Number.isNaN(v))) {
    return { available: false, reason: "Feature vector contained invalid values - ML inference skipped for safety" };
  }

  const rawProbability = predictProbaFromModel(loaded.model, featureVector);
  let calibratedProbability = rawProbability;
  let calibrationApplied = false;
  if (loaded.calibration) {
    calibratedProbability = applyPlatt(rawProbability, loaded.calibration.w, loaded.calibration.b);
    calibrationApplied = true;
  }

  return {
    available: true,
    rawProbability,
    calibratedProbability,
    calibrationApplied,
    // `phishingProbability` = the number the risk engine should use. We use
    // the calibrated value when available since it's a better-behaved
    // probability estimate; either way it remains ONE bounded-weight input,
    // never a standalone verdict.
    phishingProbability: calibratedProbability,
    featureVector,
    modelVersion: loaded.metadata ? loaded.metadata.model_version : "unknown",
  };
}
