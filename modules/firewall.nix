{
  lib,
  config,
  ...
}: let
  inherit
    (builtins)
    isList
    isAttrs
    isString
    isInt
    attrNames
    hasAttr
    all
    length
    elemAt
    elem
    filter
    mapAttrs
    ;

  inherit
    (lib)
    mkOption
    types
    optional
    flatten
    concatStringsSep
    concatMapStringsSep
    optionalString
    mkDefault
    mapAttrsToList
    mapAttrs'
    nameValuePair
    ;

  # region lib
  concatMapLinesSep = concatMapStringsSep "\n";

  hasAttrs = xs: s: all (e: hasAttr e xs) s;
  hasAttrsMatchingCondition = xs: c: s: all (e: hasAttr e xs) s;
  # endregion

  # region value mappers
  mapGenericValue = value:
    if isAttrs value
    then
      if hasAttrsMatchingCondition value isInt ["from" "to"]
      then "${toString value.from}${value.separator}${toString value.to}"
      else if hasAttrs value ["value" "mask"]
      then "${toString value.value}/${toString value.mask}"
      else throw "unhandled type"
    else if isList value
    then concatMapStringsSep "," mapGenericValue value
    else if isString value
    then value
    else if isInt value
    then toString value
    else throw "unhandled type";

  selectorDefault = options:
    if isAttrs options
    then
      if hasAttr "value" options
      then options.value
      else throw "unable to determine option value"
    else options;

  mapOption = mapFn: selector: switch: options: "${switch} ${mapFn (selector options)}";

  mapInvertibleOption = mapFn: selector: switch: options: let
    set = isAttrs options;
  in "${optionalString (set && options.invert) "! "}${mapOption mapFn selector switch options}";
  mapInvertibleOptionDefault = mapInvertibleOption mapGenericValue selectorDefault;
  # endregion

  # | prefix     | optional | "-"
  # | name       | optional | attribute name
  # | invertible | optional | false
  # | flag       | optional | false

  matcherSchemas = import ./schemas/matcher.nix {inherit lib;};
  targetSchemas = import ./schemas/target.nix {inherit lib;};

  mapArgument = name: schema: options: let
    switch = schema.name;
    prefix = schema.prefix;
    mappedValue = mapGenericValue options;
  in
    if schema.flag or false
    then "${prefix}${switch}"
    else if !isAttrs options
    then "${prefix}${switch} ${mappedValue}"
    else if !schema.invertible
    then "${prefix}${switch} ${mappedValue}"
    else "${optionalString (schema.invertible && (options.invert or false)) "! "}${prefix}${switch} ${mappedValue}";

  mapArguments = schemaSet: module: options: let
    moduleSchema = schemaSet.${module}.options or (throw "unknown module: ${module}");
    findArgumentSchema = name: let
      matching = filter (e: elem name e.names) (mapAttrsToList (k: v: {
          names = [k] ++ v.aliases;
          schema = v;
        })
        moduleSchema);
    in
      if length matching != 0
      then elemAt matching 0
      else throw "unknown argument: ${name}";
    argMapper = k: v: let
      option = options.${k} or null;
    in
      optional (!isNull option) (mapArgument k (findArgumentSchema k).schema option);
    args = mapAttrsToList argMapper moduleSchema;
  in
    concatStringsSep " " (flatten (moduleSchema.appendArgs or [] ++ args));

  mapTargetArguments = value:
    if isString value
    then value
    else mapArguments targetSchemas value.module value.options;

  makeInvertibleValueType = type:
    types.either
    type
    (types.submodule {
      options = {
        invert = mkOption {
          type = types.bool;
          default = false;
          description = "";
        };
        value = mkOption {
          type = types.nullOr type;
          default = null;
          description = "";
        };
      };
    });
  makeOptionalInvertableOption = type:
    mkOption {
      type = types.nullOr (makeInvertibleValueType type);
      default = null;
      description = "";
    };

  mapOptions = schemaSet: module: let
    optionsSchema = schemaSet.${module}.options or (throw "unknown module: ${module}");

    getOptionType = schema:
      if !schema.invertible
      then schema.type
      else makeInvertibleValueType schema.type;
  in
    mapAttrs' (k: v: let
    in
      nameValuePair k (mkOption {
        type = types.nullOr (getOptionType v);
        default = null;
        description = "";
      }))
    optionsSchema;

  moduleTypes = mapAttrs (k: _: mapOptions matcherSchemas k) (mapAttrs (_: v: builtins.trace v.options v.options) matcherSchemas);
  targetTypes = mapAttrs (k: _: mapOptions targetSchemas k) (mapAttrs (_: v: builtins.trace v.options v.options) targetSchemas);
  
  # region rule mapper
  mapRule = active: rule:
    concatStringsSep " "
    (flatten [
      (
        if rule.version == "any"
        then "ip46tables"
        else if rule.version == 4
        then "iptables"
        else "ip6tables"
      )
      "-t ${rule.table}"
      "${(
        if active
        then "-A"
        else "-D"
      )} ${rule.chain}"

      (optional (!isNull rule.input) (mapInvertibleOptionDefault "-i" rule.input))
      (optional (!isNull rule.output) (mapInvertibleOptionDefault "-o" rule.output))
      (optional (!isNull rule.source) (mapInvertibleOptionDefault "-s" rule.source))
      (optional (!isNull rule.destination) (mapInvertibleOptionDefault "-d" rule.destination))
      (optional (!isNull rule.protocol) (mapInvertibleOptionDefault "-p" rule.protocol))
      (concatMapStringsSep " " (module: "-m ${module.module} ${mapArguments matcherSchemas module.module module.options} ${module.extraArgs}") rule.modules)
      (optional (!isNull rule.target) "-j ${rule.target.module or rule.target} ${mapTargetArguments rule.target}")
      (optional (!isNull rule.goto) "-g ${rule.goto}")
      (optional (!isNull rule.comment) "-m comment --comment ${lib.escapeShellArg rule.comment}")
      (optional (!isNull rule.appendArgs) rule.appendArgs)
    ]);
  # endregion

  portRangeOptions = {
    options = {
      from = mkOption {
        type = types.port;
        description = "";
      };
      to = mkOption {
        type = types.port;
        description = "";
      };
    };
  };

  icmpTypesEnum = [
    "parameter-problem"
    "ip-header-bad"
    "required-option-missing"
    "timestamp-request"
    "timestamp-reply"
    "address-mask-request"
    "address-mask-reply"
  ];

  ruleOptions = {
    version = mkOption {
      type = types.enum [4 6 "any"];
      default = "any";
      description = "";
    };
    table = mkOption {
      type = types.enum ["filter" "nat" "mangle" "raw"];
      default = "filter";
      description = "";
    };
    chain = mkOption {
      type = types.nonEmptyStr;
      default = "nixos-fw";
      description = "";
    };
    input = makeOptionalInvertableOption (types.either types.nonEmptyStr (types.listOf types.nonEmptyStr));
    output = makeOptionalInvertableOption (types.either types.nonEmptyStr (types.listOf types.nonEmptyStr));
    source = makeOptionalInvertableOption (types.either types.nonEmptyStr (types.listOf types.nonEmptyStr));
    destination = makeOptionalInvertableOption (types.either types.nonEmptyStr (types.listOf types.nonEmptyStr));
    protocol = mkOption {
      type = types.nullOr (types.oneOf [types.int (types.enum ["tcp" "udp" "vrrp" "ah"])]);
      description = "";
      default = null;
    };
    modules = mkOption {
      type = types.listOf (types.submodule ({config, ...}: let
        moduleOptions = moduleTypes.${config.module} or (throw "unknown module: ${config.module}");
      in {
        options = {
          module = mkOption {
            type = types.either types.nonEmptyStr (types.enum (attrNames moduleTypes));
            description = "";
          };
          options = mkOption {
            type = types.nullOr (types.submodule {
              options = moduleOptions;
            });
            default = null;
            description = "";
          };
          extraArgs = mkOption {
            type=types.nullOr types.nonEmptyStr;
            default=null;
            description="";
          };
        };
      }));
      description = "";
      default = [];
    };
    appendArgs = mkOption {
      type = types.nullOr types.nonEmptyStr;
      description = "";
      default = null;
    };
    target = mkOption {
      type = types.either types.nonEmptyStr (types.submodule ({config, ...}: let
        targetOptions = targetTypes.${config.module} or (throw "unknown target: ${config.module}");
      in {
        options = {
          module = mkOption {
            type = types.either types.nonEmptyStr (types.enum (attrNames targetTypes));
            description = "";
          };
          options = mkOption {
            type = types.nullOr (types.submodule {
              options = targetOptions;
            });
            default = null;
            description = "";
          };
        };
      }));
      description = "";
      default = "nixos-fw-accept";
    };
    goto = mkOption {
      type = types.nullOr types.nonEmptyStr;
      description = "";
      default = null;
    };
    comment = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = "";
    };
  };

  ruleModule = {
    options = ruleOptions;
  };

  tcpRuleModule = {config, ...}: {
    options =
      ruleOptions
      // {
        destinationPorts = makeOptionalInvertableOption (types.listOf (types.either types.port (types.submodule portRangeOptions)));
      };
    config = {
      version = mkDefault "any";
      modules =
        [
          {
            module = "tcp";
          }
        ]
        ++ optional (config.destinationPorts != null) {
          module = "multiport";
          options.destinationPorts = config.destinationPorts;
        };
    };
  };

  udpRuleModule = {config, ...}: {
    options =
      ruleOptions
      // {
        destinationPorts = makeOptionalInvertableOption (types.listOf (types.either types.port (types.submodule portRangeOptions)));
      };
    config = {
      version = mkDefault "any";
      modules =
        [
          {
            module = "udp";
          }
        ]
        ++ optional (config.destinationPorts != null) {
          module = "multiport";
          options.destinationPorts = config.destinationPorts;
        };
    };
  };

  icmpRuleModule = {config, ...}: {
    options =
      ruleOptions
      // {
        icmpType = mkOption {
          type = types.enum icmpTypesEnum;
          description = "";
        };
      };
    config = {
      version = mkDefault "any";
      modules = [
        {
          module = "icmp";
          options.icmpType = config.icmpType;
        }
      ];
    };
  };

  toRule = proto: opts: {
    inherit
      (opts)
      version
      table
      chain
      input
      output
      source
      destination
      protocol
      modules
      appendArgs
      target
      goto
      comment
      ;
  };

  cfg = config.networking.firewall;
  rules =
    (map (toRule "tcp") cfg.rules.tcp)
    ++ (map (toRule "udp") cfg.rules.udp)
    ++ (map (toRule "icmp") cfg.rules.icmp)
    ++ cfg.rules.extra;

  extraCommands = "${concatMapLinesSep (mapRule true) rules}\n";
  extraStopCommands = "${concatMapLinesSep (rule: "${mapRule rule false} || true") rules}\n";
in {
  options = {
    networking.firewall = {
      rules = {
        tcp = mkOption {
          type = types.listOf (types.submodule tcpRuleModule);
          default = [];
          description = "TCP firewall rules.";
        };
        udp = mkOption {
          type = types.listOf (types.submodule udpRuleModule);
          default = [];
          description = "UDP firewall rules.";
        };
        icmp = mkOption {
          type = types.listOf (types.submodule icmpRuleModule);
          default = [];
          description = "ICMP firewall rules.";
        };
        extra = mkOption {
          type = types.listOf (types.submodule ruleModule);
          default = [];
          description = "Extra firewall rules.";
        };
      };
    };
  };
  config = {
    networking.firewall = {
      inherit extraCommands;
      inherit extraStopCommands;
    };
  };
}
