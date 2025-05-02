{lib, ...}: let
  inherit (lib) mkOption types;

  rangeOptions = separator: type: {
    options = {
      separator = mkOption {
        type = types.nonEmptyStr;
        default = separator;
        description = "";
      };
      from = mkOption {
        inherit type;
        description = "";
      };
      to = mkOption {
        inherit type;
        description = "";
      };
    };
  };
  valueMaskOptions = valueType: maskType: {
    options = {
      value = mkOption {
        type = valueType;
        description = "";
      };
      mask = mkOption {
        type = maskType;
        description = "";
      };
    };
  };
in rec {
  rangeType = separator: type: types.submodule rangeOptions;
  valueOrValueRangeType = separator: type: types.either type (rangeType separator type);
  intOrIntRange = valueOrValueRangeType ":" types.int;
  portOrPortRange = valueOrValueRangeType ":" types.port;
  ipRange = rangeType "-" types.nonEmptyStr;
  valueWithMaskType = valueType: maskType: types.submodule (valueMaskOptions valueType maskType);
  valueWithOptionalMaskType = valueType: maskType: valueWithMaskType valueType (types.nullOr maskType);
  stringValueWithOptionalStringMaskType = valueWithOptionalMaskType types.nonEmptyStr types.nonEmptyStr;
  stringValueWithOptionalIntMaskType = valueWithOptionalMaskType types.nonEmptyStr types.int;
}
