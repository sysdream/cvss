export var BaseMetric;
(function (BaseMetric) {
    BaseMetric["ATTACK_VECTOR"] = "AV";
    BaseMetric["ATTACK_COMPLEXITY"] = "AC";
    BaseMetric["PRIVILEGES_REQUIRED"] = "PR";
    BaseMetric["USER_INTERACTION"] = "UI";
    BaseMetric["SCOPE"] = "S";
    BaseMetric["CONFIDENTIALITY"] = "C";
    BaseMetric["INTEGRITY"] = "I";
    BaseMetric["AVAILABILITY"] = "A";
})(BaseMetric || (BaseMetric = {}));
export var TemporalMetric;
(function (TemporalMetric) {
    TemporalMetric["EXPLOITABILITY"] = "E";
    TemporalMetric["REMEDIATION_LEVEL"] = "RL";
    TemporalMetric["REPORT_CONFIDENCE"] = "RC";
})(TemporalMetric || (TemporalMetric = {}));
export var EnvironmentalMetric;
(function (EnvironmentalMetric) {
    EnvironmentalMetric["ATTACK_VECTOR"] = "MAV";
    EnvironmentalMetric["ATTACK_COMPLEXITY"] = "MAC";
    EnvironmentalMetric["PRIVILEGES_REQUIRED"] = "MPR";
    EnvironmentalMetric["USER_INTERACTION"] = "MUI";
    EnvironmentalMetric["SCOPE"] = "MS";
    EnvironmentalMetric["CONFIDENTIALITY"] = "MC";
    EnvironmentalMetric["INTEGRITY"] = "MI";
    EnvironmentalMetric["AVAILABILITY"] = "MA";
    EnvironmentalMetric["CONFIDENTIALITY_REQUIREMENT"] = "CR";
    EnvironmentalMetric["INTEGRITY_REQUIREMENT"] = "IR";
    EnvironmentalMetric["AVAILABILITY_REQUIREMENT"] = "AR";
})(EnvironmentalMetric || (EnvironmentalMetric = {}));
export const baseMetricMap = [
    BaseMetric.ATTACK_VECTOR,
    BaseMetric.ATTACK_COMPLEXITY,
    BaseMetric.PRIVILEGES_REQUIRED,
    BaseMetric.USER_INTERACTION,
    BaseMetric.SCOPE,
    BaseMetric.CONFIDENTIALITY,
    BaseMetric.INTEGRITY,
    BaseMetric.AVAILABILITY
];
export const temporalMetricMap = [
    TemporalMetric.EXPLOITABILITY,
    TemporalMetric.REMEDIATION_LEVEL,
    TemporalMetric.REPORT_CONFIDENCE
];
export const environmentalMetricMap = [
    EnvironmentalMetric.ATTACK_VECTOR,
    EnvironmentalMetric.ATTACK_COMPLEXITY,
    EnvironmentalMetric.PRIVILEGES_REQUIRED,
    EnvironmentalMetric.USER_INTERACTION,
    EnvironmentalMetric.SCOPE,
    EnvironmentalMetric.CONFIDENTIALITY,
    EnvironmentalMetric.INTEGRITY,
    EnvironmentalMetric.AVAILABILITY,
    EnvironmentalMetric.AVAILABILITY_REQUIREMENT,
    EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT,
    EnvironmentalMetric.INTEGRITY_REQUIREMENT
];
export const baseMetricValues = {
    [BaseMetric.ATTACK_VECTOR]: ['N', 'A', 'L', 'P'],
    [BaseMetric.ATTACK_COMPLEXITY]: ['L', 'H'],
    [BaseMetric.PRIVILEGES_REQUIRED]: ['N', 'L', 'H'],
    [BaseMetric.USER_INTERACTION]: ['N', 'R'],
    [BaseMetric.SCOPE]: ['U', 'C'],
    [BaseMetric.CONFIDENTIALITY]: ['N', 'L', 'H'],
    [BaseMetric.INTEGRITY]: ['N', 'L', 'H'],
    [BaseMetric.AVAILABILITY]: ['N', 'L', 'H']
};
export const environmentalMetricValues = {
    [EnvironmentalMetric.ATTACK_VECTOR]: ['N', 'A', 'L', 'P', 'X'],
    [EnvironmentalMetric.ATTACK_COMPLEXITY]: ['L', 'H', 'X'],
    [EnvironmentalMetric.PRIVILEGES_REQUIRED]: ['N', 'L', 'H', 'X'],
    [EnvironmentalMetric.USER_INTERACTION]: ['N', 'R', 'X'],
    [EnvironmentalMetric.SCOPE]: ['U', 'C', 'X'],
    [EnvironmentalMetric.CONFIDENTIALITY]: ['N', 'L', 'H', 'X'],
    [EnvironmentalMetric.INTEGRITY]: ['N', 'L', 'H', 'X'],
    [EnvironmentalMetric.AVAILABILITY]: ['N', 'L', 'H', 'X'],
    [EnvironmentalMetric.CONFIDENTIALITY_REQUIREMENT]: ['M', 'L', 'H', 'X'],
    [EnvironmentalMetric.INTEGRITY_REQUIREMENT]: ['M', 'L', 'H', 'X'],
    [EnvironmentalMetric.AVAILABILITY_REQUIREMENT]: ['M', 'L', 'H', 'X']
};
export const temporalMetricValues = {
    [TemporalMetric.EXPLOITABILITY]: ['X', 'U', 'P', 'F', 'H'],
    [TemporalMetric.REMEDIATION_LEVEL]: ['X', 'O', 'T', 'W', 'U'],
    [TemporalMetric.REPORT_CONFIDENCE]: ['X', 'U', 'R', 'C']
};
export const metricsIndex = {
    MAV: BaseMetric.ATTACK_VECTOR,
    MAC: BaseMetric.ATTACK_COMPLEXITY,
    MPR: BaseMetric.PRIVILEGES_REQUIRED,
    MUI: BaseMetric.USER_INTERACTION,
    MS: BaseMetric.SCOPE,
    MC: BaseMetric.CONFIDENTIALITY,
    MI: BaseMetric.INTEGRITY,
    MA: BaseMetric.AVAILABILITY
};
