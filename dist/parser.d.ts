import { Metric, MetricValue } from './models';
export interface KeyValue<K, V> {
    key: K;
    value: V;
}
export declare const parseVersion: (cvssStr: string) => string | null;
export declare const parseVector: (cvssStr: string) => string | null;
export declare const parseMetrics: (vectorStr: string) => KeyValue<string, string>[];
export declare const parseMetricsAsMap: (cvssStr: string) => Map<Metric, MetricValue>;
