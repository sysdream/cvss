const VERSION_REGEX = /^CVSS:(\d(?:\.\d)?)(.*)?$/;
export const parseVersion = (cvssStr) => {
    const versionRegexRes = VERSION_REGEX.exec(cvssStr);
    return versionRegexRes && versionRegexRes[1];
};
export const parseVector = (cvssStr) => {
    const versionRegexRes = VERSION_REGEX.exec(cvssStr);
    return versionRegexRes && versionRegexRes[2] && versionRegexRes[2].substr(1);
};
export const parseMetrics = (vectorStr) => (vectorStr ? vectorStr.split('/') : []).map((metric) => {
    if (!metric) {
        return { key: '', value: '' };
    }
    const parts = metric.split(':');
    return { key: parts[0], value: parts[1] };
});
export const parseMetricsAsMap = (cvssStr) => parseMetrics(parseVector(cvssStr) || '').reduce((res, metric) => {
    if (res.has(metric.key)) {
        throw new Error(`Duplicated metric: "${metric.key}:${metric.value || ''}"`);
    }
    return res.set(metric.key, metric.value);
}, new Map());
