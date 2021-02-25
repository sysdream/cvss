export declare enum BaseMetric {
    ATTACK_VECTOR = "AV",
    ATTACK_COMPLEXITY = "AC",
    PRIVILEGES_REQUIRED = "PR",
    USER_INTERACTION = "UI",
    SCOPE = "S",
    CONFIDENTIALITY = "C",
    INTEGRITY = "I",
    AVAILABILITY = "A"
}
export declare enum TemporalMetric {
    EXPLOITABILITY = "E",
    REMEDIATION_LEVEL = "RL",
    REPORT_CONFIDENCE = "RC"
}
export declare enum EnvironmentalMetric {
    ATTACK_VECTOR = "MAV",
    ATTACK_COMPLEXITY = "MAC",
    PRIVILEGES_REQUIRED = "MPR",
    USER_INTERACTION = "MUI",
    SCOPE = "MS",
    CONFIDENTIALITY = "MC",
    INTEGRITY = "MI",
    AVAILABILITY = "MA",
    CONFIDENTIALITY_REQUIREMENT = "CR",
    INTEGRITY_REQUIREMENT = "IR",
    AVAILABILITY_REQUIREMENT = "AR"
}
export declare const baseMetricMap: ReadonlyArray<BaseMetric>;
export declare const temporalMetricMap: Metrics<TemporalMetric>;
export declare const environmentalMetricMap: Metrics<EnvironmentalMetric>;
export declare const baseMetricValues: MetricValues<BaseMetric, BaseMetricValue>;
export declare const environmentalMetricValues: MetricValues<EnvironmentalMetric, EnvironmentalMetricValue>;
export declare const temporalMetricValues: MetricValues<TemporalMetric, TemporalMetricValue>;
export declare const metricsIndex: {
    [key: string]: BaseMetric;
};
export declare type Metric = BaseMetric | TemporalMetric | EnvironmentalMetric;
export declare type AnyMetric = BaseMetric & TemporalMetric & EnvironmentalMetric;
export declare type BaseMetricValue = 'A' | 'C' | 'H' | 'L' | 'N' | 'P' | 'R' | 'U';
export declare type TemporalMetricValue = 'X' | 'F' | 'H' | 'O' | 'T' | 'W' | 'U' | 'P' | 'C' | 'R';
export declare type EnvironmentalMetricValue = BaseMetricValue | 'M' | 'X';
export declare type MetricValue = BaseMetricValue | TemporalMetricValue | EnvironmentalMetricValue | any;
export declare type MetricValues<M extends Metric = Metric, V extends MetricValue = MetricValue> = Record<M, V[]>;
export declare type Metrics<M = Metric> = ReadonlyArray<M>;
export declare type AllMetricValues = typeof baseMetricValues | typeof temporalMetricValues | typeof environmentalMetricValues;
