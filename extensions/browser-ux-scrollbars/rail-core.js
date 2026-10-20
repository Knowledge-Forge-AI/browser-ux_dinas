"use strict";

// Pure DOM-free rail core logic, geometry, scheduler, and boundary constraints.
var BrowserUxRailCore = (function () {
  const LIMITS = Object.freeze({
    SLICE_NODES: 1500,
    SLICE_MS: 4,
    SCAN_TOTAL: 60000,
    MAX_PENDING: 512,
    MAX_CANDIDATES: 256,
    MAX_RAILS: 24,
    MAX_SHADOWS: 64,
    MAX_ANCESTORS: 64,
    MIN_TRACK: 32,
    MIN_THUMB: 20,
    MIN_THICKNESS: 6,
    MAX_THICKNESS: 32,
    TIMEOUT_MS: 5000,
    SENTINEL_LIVENESS_MS: 3000,
    COVERAGE_ROOTS: 256,
    COVERAGE_WORK_NODES: 60000,
    RESUME_DELAY_MS: 150,
    POLL_SHOWN_MS: 1000,
    LIMITED_COOLDOWN_MS: 60000,
    REFUSED_COOLDOWN_MIN_MS: 30000,
    REFUSED_COOLDOWN_MAX_MS: 300000,
    PATHOLOGICAL_PASSES: 3,
    PATHOLOGICAL_DURATION_MS: 12,
    LINE_HEIGHT: 16,
    PAGE_RATIO: 0.875,
  });

  const STATES = Object.freeze({
    ACTIVE: "ACTIVE",
    SUSPENDED: "SUSPENDED",
    LIMITED: "LIMITED",
    REFUSED: "REFUSED",
    HOST_STYLE_CONTESTED: "HOST_STYLE_CONTESTED",
    HOST_CONTESTED: "HOST_CONTESTED",
    ROOT_GUTTER_UNPAINTABLE: "ROOT_GUTTER_UNPAINTABLE",
  });

  function clamp(value, min, max) {
    if (typeof value !== "number" || Number.isNaN(value)) {
      return min;
    }
    return Math.max(min, Math.min(max, value));
  }

  function computeThumbGeometry(params) {
    const scrollSize = params && params.scrollSize > 0 ? params.scrollSize : 0;
    const clientSize = params && params.clientSize > 0 ? params.clientSize : 0;
    const scrollPos = params && params.scrollPos > 0 ? params.scrollPos : 0;
    const trackLength = params && params.trackLength > 0 ? params.trackLength : 0;
    const minThumb =
      params && typeof params.minThumb === "number"
        ? Math.max(1, params.minThumb)
        : LIMITS.MIN_THUMB;

    const scrollRange = Math.max(0, scrollSize - clientSize);
    if (scrollRange <= 0 || trackLength <= 0 || clientSize <= 0) {
      return {
        thumbLength: 0,
        thumbOffset: 0,
        trackTravel: 0,
        scrollRange: 0,
        visible: false,
      };
    }

    const rawThumb = (clientSize / scrollSize) * trackLength;
    const thumbLength = Math.max(
      Math.min(minThumb, trackLength),
      Math.min(trackLength, Math.round(rawThumb)),
    );
    const trackTravel = Math.max(0, trackLength - thumbLength);
    const ratio = scrollRange > 0 ? clamp(scrollPos / scrollRange, 0, 1) : 0;
    const thumbOffset = Math.round(ratio * trackTravel);

    return {
      thumbLength,
      thumbOffset,
      trackTravel,
      scrollRange,
      visible: true,
    };
  }

  function thumbOffsetToScrollPos(params) {
    const thumbOffset = params && params.thumbOffset ? params.thumbOffset : 0;
    const thumbLength = params && params.thumbLength ? params.thumbLength : 0;
    const trackLength = params && params.trackLength ? params.trackLength : 0;
    const scrollRange = params && params.scrollRange ? params.scrollRange : 0;

    const trackTravel = Math.max(0, trackLength - thumbLength);
    if (trackTravel <= 0 || scrollRange <= 0) {
      return 0;
    }
    const ratio = clamp(thumbOffset / trackTravel, 0, 1);
    return Math.round(ratio * scrollRange);
  }

  function computeWheelScroll(params) {
    const deltaMode = params && params.deltaMode ? params.deltaMode : 0;
    const rawDeltaX = params && typeof params.deltaX === "number" ? params.deltaX : 0;
    const rawDeltaY = params && typeof params.deltaY === "number" ? params.deltaY : 0;
    const clientWidth = params && params.clientWidth > 0 ? params.clientWidth : 100;
    const clientHeight = params && params.clientHeight > 0 ? params.clientHeight : 100;
    const lineHeight =
      params && typeof params.lineHeight === "number"
        ? params.lineHeight
        : LIMITS.LINE_HEIGHT;

    let multiplierX = 1;
    let multiplierY = 1;
    if (deltaMode === 1) {
      // DOM_DELTA_LINE
      multiplierX = lineHeight;
      multiplierY = lineHeight;
    } else if (deltaMode === 2) {
      // DOM_DELTA_PAGE
      multiplierX = clientWidth;
      multiplierY = clientHeight;
    }

    return {
      scrollDeltaX: rawDeltaX * multiplierX,
      scrollDeltaY: rawDeltaY * multiplierY,
    };
  }

  function computeTrackStep(params) {
    const clickOffset = params && typeof params.clickOffset === "number" ? params.clickOffset : 0;
    const thumbOffset = params && typeof params.thumbOffset === "number" ? params.thumbOffset : 0;
    const thumbLength = params && typeof params.thumbLength === "number" ? params.thumbLength : 0;
    const clientLength = params && typeof params.clientLength === "number" ? params.clientLength : 0;
    const pageSizeRatio =
      params && typeof params.pageSizeRatio === "number"
        ? params.pageSizeRatio
        : LIMITS.PAGE_RATIO;

    const step = Math.round(clientLength * pageSizeRatio);
    if (clickOffset < thumbOffset) {
      return { direction: -1, stepDelta: -step };
    }
    if (clickOffset > thumbOffset + thumbLength) {
      return { direction: 1, stepDelta: step };
    }
    return { direction: 0, stepDelta: 0 };
  }

  function intersectRects(rectA, rectB) {
    if (!rectA || !rectB) {
      return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, empty: true };
    }
    const top = Math.max(rectA.top, rectB.top);
    const left = Math.max(rectA.left, rectB.left);
    const bottom = Math.min(rectA.bottom, rectB.bottom);
    const right = Math.min(rectA.right, rectB.right);
    const width = Math.max(0, right - left);
    const height = Math.max(0, bottom - top);
    const empty = width <= 0 || height <= 0;
    return { top, left, bottom, right, width, height, empty };
  }

  function isIdentityTransform(transformStr) {
    if (!transformStr || transformStr === "none" || transformStr === "") {
      return true;
    }
    // Check 2D matrix
    const matrixMatch = transformStr.match(/^matrix\(([^)]+)\)$/);
    if (matrixMatch) {
      const parts = matrixMatch[1].split(",").map((p) => parseFloat(p.trim()));
      if (parts.length === 6) {
        const [a, b, c, d, e, f] = parts;
        return (
          Math.abs(a - 1) < 1e-4 &&
          Math.abs(b) < 1e-4 &&
          Math.abs(c) < 1e-4 &&
          Math.abs(d - 1) < 1e-4 &&
          Math.abs(e) < 1e-4 &&
          Math.abs(f) < 1e-4
        );
      }
      return false;
    }
    // Check 3D matrix
    const matrix3dMatch = transformStr.match(/^matrix3d\(([^)]+)\)$/);
    if (matrix3dMatch) {
      const parts = matrix3dMatch[1].split(",").map((p) => parseFloat(p.trim()));
      if (parts.length === 16) {
        const identity = [
          1, 0, 0, 0,
          0, 1, 0, 0,
          0, 0, 1, 0,
          0, 0, 0, 1,
        ];
        return parts.every((val, idx) => Math.abs(val - identity[idx]) < 1e-4);
      }
      return false;
    }
    return false;
  }

  function validateGutter(gutter, nativeThickness, tolerance) {
    const tol = typeof tolerance === "number" ? tolerance : 1;
    if (typeof gutter !== "number" || typeof nativeThickness !== "number") {
      return false;
    }
    if (gutter < LIMITS.MIN_THICKNESS || gutter > LIMITS.MAX_THICKNESS) {
      return false;
    }
    return Math.abs(gutter - nativeThickness) <= tol;
  }

  return {
    LIMITS,
    STATES,
    clamp,
    computeThumbGeometry,
    thumbOffsetToScrollPos,
    computeWheelScroll,
    computeTrackStep,
    intersectRects,
    isIdentityTransform,
    validateGutter,
  };
})();

