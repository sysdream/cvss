import { Metric, MetricValue } from './models';
export declare const humanizeBaseMetric: (metric: Metric) => string;
export declare const humanizeBaseMetricValue: (value: MetricValue, metric: Metric) => string;
/**
 * Stringify a score into a qualitative severity rating string
 * @param score
 */
export declare const humanizeScore: (score: number) => string;
