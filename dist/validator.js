import { baseMetricMap, temporalMetricMap, environmentalMetricMap, baseMetricValues, temporalMetricValues, environmentalMetricValues } from './models';
import { humanizeBaseMetric, humanizeBaseMetricValue } from './humanizer';
import { parseMetricsAsMap, parseVector, parseVersion } from './parser';
export const validateVersion = (versionStr) => {
    if (!versionStr) {
        throw new Error('Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L');
    }
    if (versionStr !== '3.0' && versionStr !== '3.1') {
        throw new Error(`Unsupported CVSS version: ${versionStr}. Only 3.0 and 3.1 are supported`);
    }
};
const validateVector = (vectorStr) => {
    if (!vectorStr || vectorStr.includes('//')) {
        throw new Error('Invalid CVSS string. Example: CVSS:3.0/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L');
    }
};
const checkUnknownMetrics = (metricsMap, knownMetrics) => {
    const allKnownMetrics = knownMetrics || [
        ...baseMetricMap,
        ...temporalMetricMap,
        ...environmentalMetricMap
    ];
    [...metricsMap.keys()].forEach((userMetric) => {
        if (!allKnownMetrics.includes(userMetric)) {
            throw new Error(`Unknown CVSS metric "${userMetric}". Allowed metrics: ${allKnownMetrics.join(', ')}`);
        }
    });
};
const checkMandatoryMetrics = (metricsMap, metrics = baseMetricMap) => {
    metrics.forEach((metric) => {
        if (!metricsMap.has(metric)) {
            // eslint-disable-next-line max-len
            throw new Error(`Missing mandatory CVSS metric ${metrics} (${humanizeBaseMetric(metric)})`);
        }
    });
};
const checkMetricsValues = (metricsMap, metrics, metricsValues) => {
    metrics.forEach((metric) => {
        const userValue = metricsMap.get(metric);
        if (!userValue) {
            return;
        }
        if (!metricsValues[metric].includes(userValue)) {
            const allowedValuesHumanized = metricsValues[metric]
                .map((value) => `${value} (${humanizeBaseMetricValue(value, metric)})`)
                .join(', ');
            throw new Error(`Invalid value for CVSS metric ${metric} (${humanizeBaseMetric(metric)})${userValue ? `: ${userValue}` : ''}. Allowed values: ${allowedValuesHumanized}`);
        }
    });
};
/**
 * Validate that the given string is a valid cvss vector
 * @param cvssStr
 */
export const validate = (cvssStr) => {
    if (!cvssStr || !cvssStr.startsWith('CVSS:')) {
        throw new Error('CVSS vector must start with "CVSS:"');
    }
    const allKnownMetrics = [
        ...baseMetricMap,
        ...temporalMetricMap,
        ...environmentalMetricMap
    ];
    const allKnownMetricsValues = {
        ...baseMetricValues,
        ...temporalMetricValues,
        ...environmentalMetricValues
    };
    const versionStr = parseVersion(cvssStr);
    validateVersion(versionStr);
    const vectorStr = parseVector(cvssStr);
    validateVector(vectorStr);
    const metricsMap = parseMetricsAsMap(cvssStr);
    checkMandatoryMetrics(metricsMap);
    checkUnknownMetrics(metricsMap, allKnownMetrics);
    checkMetricsValues(metricsMap, allKnownMetrics, allKnownMetricsValues);
    const isTemporal = [...metricsMap.keys()].some((metric) => temporalMetricMap.includes(metric));
    const isEnvironmental = [...metricsMap.keys()].some((metric) => environmentalMetricMap.includes(metric));
    return {
        metricsMap,
        isTemporal,
        isEnvironmental,
        versionStr
    };
};
