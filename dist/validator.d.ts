import { Metric, MetricValue } from './models';
export declare const validateVersion: (versionStr: string | null) => void;
declare type ValidationResult = {
    isTemporal: boolean;
    isEnvironmental: boolean;
    metricsMap: Map<Metric, MetricValue>;
    versionStr: string | null;
};
/**
 * Validate that the given string is a valid cvss vector
 * @param cvssStr
 */
export declare const validate: (cvssStr: string) => ValidationResult;
export {};
