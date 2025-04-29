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
    ;

  # region value mappers
  mapGenericValue = value:
    if isAttrs value
    then
      if all (e: hasAttr e value) ["start" "end"]
      then "${toString value.start}:${toString value.end}"
      else if all (e: hasAttr e.value) ["start" "end"]
      then "${toString value.start}:${toString value.end}"
      else throw "unhandled type"
    else if isList value
    then concatMapStringsSep "," mapGenericValue value
    else if isString value
    then value
    else if isInt value
    then toString value
    else throw "unhandled type";

  mapPortValue = value:
    if isInt value
    then toString value
    else if isList value
    then concatMapStringsSep "," mapPortValue value
    else if isAttrs value
    then "${toString value.start}:${toString value.end}"
    else throw "unhandled type";

  selectorDefault = options:
    if isAttrs options
    then
      if hasAttr "value" options
      then options.value
      else throw "unable to determine option value"
    else options;

  mapOption = mapFn: selector: switch: options: "${switch} ${mapFn (selector options)}";
  mapOptionDefault = mapOption mapGenericValue selectorDefault;

  mapInvertibleOption = mapFn: selector: switch: options: let
    set = isAttrs options;
  in "${optionalString (set && options.invert) "! "}${mapOption mapFn selector switch options}";
  mapInvertibleOptionDefault = mapInvertibleOption mapGenericValue selectorDefault;
  # endregion

  # region module mapper
  mapModuleOptions = module: options: let
    mapOpts = {
      addrtype = options:
        optional (!isNull options) [
          (optional (!isNull options.srcType) (mapInvertibleOptionDefault "--src-type" options.srcType))
          (optional (!isNull options.dstType) (mapInvertibleOptionDefault "--dst-type" options.dstType))
          (optional (!isNull options.limitIfaceIn) "--limit-iface-in")
          (optional (!isNull options.limitIfaceOut) "--limit-iface-out")
        ];
      conntrack = options:
        optional (!isNull options) [
          (optional (!isNull options.ctstate) (mapInvertibleOptionDefault "--ctstate" options.ctstate))
          (optional (!isNull options.ctorigsrc) (mapInvertibleOptionDefault "--ctorigsrc" options.ctorigsrc))
          (optional (!isNull options.ctrepldst) (mapInvertibleOptionDefault "--ctrepldst" options.ctrepldst))
          (optional (!isNull options.ctreplsrc) (mapInvertibleOptionDefault "--ctreplsrc" options.ctreplsrc))
          (optional (!isNull options.ctrepldst) (mapInvertibleOptionDefault "--ctrepldst" options.ctrepldst))
          (optional (!isNull options.ctorigsrcport) (mapInvertibleOptionDefault "--ctorigsrcport" options.ctorigsrcport))
          (optional (!isNull options.ctorigdstport) (mapInvertibleOptionDefault "--ctorigdstport" options.ctorigdstport))
          (optional (!isNull options.ctreplsrcport) (mapInvertibleOptionDefault "--ctreplsrcport" options.ctreplsrcport))
          (optional (!isNull options.ctrepldstport) (mapInvertibleOptionDefault "--ctrepldstport" options.ctrepldstport))
          (optional (!isNull options.ctstatus) (mapInvertibleOptionDefault "--ctstatus" options.ctstatus))
        ];
      tcp = options:
        ["-p tcp"]
        ++ (optional (!isNull options) [
          (optional (!isNull options.sourcePort) (mapOptionDefault "--source-port" options.sourcePort))
          (optional (!isNull options.destinationPort) (mapOptionDefault "--destination-port" options.destinationPort))
        ]);
      udp = options:
        ["-p udp"]
        ++ (optional (!isNull options) [
          (optional (!isNull options.sourcePort) (mapOptionDefault "--source-port" options.sourcePort))
          (optional (!isNull options.destinationPort) (mapOptionDefault "--destination-port" options.destinationPort))
        ]);
      icmp = options:
        ["-p icmp"]
        ++ (optional (!isNull options [
          (optional (!isNull options.icmpType) (mapInvertibleOptionDefault "--icmp-type" options.icmpType.type))
        ]));
      multiport = options:
        optional (!isNull options) [
          (optional (!isNull options.sourcePorts) (mapInvertibleOptionDefault "--source-ports" options.sourcePorts))
          (optional (!isNull options.destinationPorts) (mapInvertibleOptionDefault "--destination-ports" options.destinationPorts))
          (optional (!isNull options.ports) (mapInvertibleOptionDefault "--ports" options.ports))
        ];
      mark = options:
        optional (!isNull options) [
          "--mark ${options.mark.value}${optionalString (!isNull options.mark.mask) "/${options.mark.mask}"}"
        ];
    };
    fn = mapOpts.${module};
  in
    concatStringsSep " " (flatten (fn options));
  # endregion

  # region target mapper
  mapTargetOptions = target: let
    mapOpts = {
      balance = options:
        optional (!isNull options) [
          "BALANCE"
          (optional (!isNull options.toDestination) "--to-destination ${options.toDestination}")
        ];
      classify = options:
        optional (!isNull options) [
          "CLASSIFY"
        ];
      clusterip = options:
        optional (!isNull options) [
          "CLUSTERIP"
        ];
      connmark = options:
        optional (!isNull options) [
          "CONNMARK"
        ];
      dnat = options:
        optional (!isNull options) [
          "DNAT"
          (optional (!isNull options.toDestination) "--to-destination ${options.toDestination}")
        ];
      dscp = options:
        optional (!isNull options) [
          "DSCP"
        ];
      ecn = options:
        optional (!isNull options) [
          "ECN"
        ];
      ipmark = options:
        optional (!isNull options) [
          "IPMARK"
        ];
      ipv4optsstrip = options:
        optional (!isNull options) [
          "IPV4OPTSSTRIP"
        ];
      log = options:
        optional (!isNull options) [
          "LOG"
          (optional (!isNull options.level) "--log-level ${options.level}")
          (optional (!isNull options.prefix) "--log-prefix ${options.prefix}")
          (optional (!isNull options.tcpSequence) "--log-tcp-sequence")
          (optional (!isNull options.tcpOptions) "--log-tcp-options")
          (optional (!isNull options.ipOptions) "--log-ip-options")
          (optional (!isNull options.uid) "--log-uid")
        ];
      mark = options:
        optional (!isNull options) [
          "MARK"
          (optional (!isNull options.mark) "--set-mark ${options.mark.value}${optionalString (!isNull options.mark.mask) "/${options.mark.mask}"}")
          (optional (!isNull options.xmark) "--set-xmark ${options.xmark.value}${optionalString (!isNull options.xmark.mask) "/${options.xmark.mask}"}")
          (optional (!isNull options.andMark) "--and-mark ${options.andMark}")
          (optional (!isNull options.orMark) "--or-mark ${options.orMark}")
          (optional (!isNull options.xorMark) "--xor-mark ${options.xorMark}")
        ];
      masquerade = options:
        optional (!isNull options) [
          "MASQUERADE"
          (optional (!isNull options.toPorts) "--to-ports ${options.toPorts}")
        ];
      mirror = options:
        optional (!isNull options) [
          "MIRROR"
        ];
      netmap = options:
        optional (!isNull options) [
          "NETMAP"
        ];
      nfqueue = options:
        optional (!isNull options) [
          "NFQUEUE"
        ];
      notrack = options:
        optional (!isNull options) [
          "NOTRACK"
        ];
      redirect = options:
        optional (!isNull options) [
          "REDIRECT"
          (optional (!isNull options.toPorts) "--to-ports ${mapPortValue options.toPorts}")
          (optional (!isNull options.random) "--random")
        ];
      same = options:
        optional (!isNull options) [
          "SAME"
        ];
      set = options:
        optional (!isNull options) [
          "SET"
        ];
      snat = options:
        optional (!isNull options) [
          "SNAT"
          (optional (!isNull options.toSource) "--to-source ${options.toSource}")
        ];
      tarpit = options:
        optional (!isNull options) [
          "TARPIT"
        ];
      tcpmss = options:
        optional (!isNull options) [
          "TCPMSS"
        ];
      trace = options:
        optional (!isNull options) [
          "TRACE"
        ];
      ttl = options:
        optional (!isNull options) [
          "TTL"
        ];
      ulog = options:
        optional (!isNull options) [
          "ULOG"
        ];
      xor = options:
        optional (!isNull options) [
          "XOR"
        ];
    };
    fn = mapOpts.${target.module};
  in
    if isString target
    then target
    else (concatStringsSep " " (flatten (fn target.options)));
  # endregion

  # region rule mapper
  mapRule = rule: active:
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
      (concatMapStringsSep " " (module: "-m ${module.module} ${mapModuleOptions module.module module.options}") rule.modules)
      (optional (!isNull rule.target) "-j ${mapTargetOptions rule.target}")
      (optional (!isNull rule.goto) "-g ${rule.goto}")
      (optional (!isNull rule.comment) "-m comment --comment ${lib.escapeShellArg rule.comment}")
      (optional (!isNull rule.extraArgs) rule.extraArgs)
    ]);
  # endregion

  addrTypesEnum = [
    "UNSPEC"
    "UNICAST"
    "LOCAL"
    "BROADCAST"
    "ANYCAST"
    "MULTICAST"
    "BLACKHOLE"
    "UNREACHABLE"
    "PROHIBIT"
    "THROW"
    "NAT"
    "XRESOLVE"
  ];

  portRangeOptions = {
    options = {
      start = mkOption {
        type = types.port;
        description = "";
      };
      end = mkOption {
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

  ctstateEnum = [
    "INVALID"
    "NEW"
    "ESTABLISHED"
    "RELATED"
    "UNTRACKED"
    "SNAT"
    "DNAT"
  ];
  ctstatusEnum = [
    "NONE"
    "EXPECTED"
    "SEEN_REPLY"
    "ASSURED"
    "CONFIRMED"
  ];

  invertible = type: {
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

  mkInvertibleOption = type:
    mkOption {
      type = types.nullOr (types.either type (types.submodule {options = invertible type;}));
      default = null;
      description = "";
    };

  valueMaskSubmodule = valueType: maskType:
    types.submodule {
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
  stringMaskSubmodule = valueMaskSubmodule types.nonEmptyStr types.nonEmptyStr;
  ipMaskSubmodule = valueMaskSubmodule types.nonEmptyStr types.int;

  moduleSettingsOptions = {
    addrtype = {
      options = {
        srcType = mkInvertibleOption (types.enum addrTypesEnum);
        dstType = mkInvertibleOption (types.enum addrTypesEnum);
        limitIfaceIn = mkOption {
          type = types.nullOr types.bool;
          default = null;
          description = "";
        };
        limitIfaceOut = mkOption {
          type = types.nullOr types.bool;
          default = null;
          description = "";
        };
      };
    };
    multiport = {
      options = {
        sourcePorts = mkInvertibleOption (types.oneOf [
          types.port
          (types.submodule portRangeOptions)
          (types.listOf (types.either types.port (types.submodule portRangeOptions)))
        ]);
        destinationPorts = mkInvertibleOption (types.oneOf [
          types.port
          (types.submodule portRangeOptions)
          (types.listOf (types.either types.port (types.submodule portRangeOptions)))
        ]);
        ports = mkInvertibleOption (types.oneOf [
          types.port
          (types.submodule portRangeOptions)
          (types.listOf (types.either types.port (types.submodule portRangeOptions)))
        ]);
      };
    };
    tcp = {
      options = {
        sourcePort = mkInvertibleOption types.port;
        destinationPort = mkInvertibleOption types.port;
        tcpFlags = mkInvertibleOption (types.listOf (types.enum [
          "SYN"
          "ACK"
          "FIN"
          "RST"
          "URG"
          "PSH"
          "ALL"
          "NONE"
        ]));
        syn = mkInvertibleOption types.bool;
        tcpOption = mkInvertibleOption types.int;
      };
    };
    udp = {
      options = {
        sourcePort = mkInvertibleOption types.port;
        destinationPort = mkInvertibleOption types.port;
      };
    };
    mark = {
      options = {
        mark = mkInvertibleOption stringMaskSubmodule;
      };
    };
    conntrack = {
      options = {
        ctstate = mkInvertibleOption (types.either (types.enum ctstateEnum) (types.listOf (types.enum ctstateEnum)));
        ctorigsrc = mkInvertibleOption ipMaskSubmodule;
        ctorigdst = mkInvertibleOption ipMaskSubmodule;
        ctreplsrc = mkInvertibleOption ipMaskSubmodule;
        ctrepldst = mkInvertibleOption ipMaskSubmodule;
        ctorigsrcport = mkInvertibleOption (types.either types.port (types.submodule portRangeOptions));
        ctorigdstport = mkInvertibleOption (types.either types.port (types.submodule portRangeOptions));
        ctreplsrcport = mkInvertibleOption (types.either types.port (types.submodule portRangeOptions));
        ctrepldstport = mkInvertibleOption (types.either types.port (types.submodule portRangeOptions));
        ctstatus = mkInvertibleOption (types.either (types.enum ctstatusEnum) (types.listOf (types.enum ctstatusEnum)));
        ctexpire = mkInvertibleOption types.string;
      };
    };
    icmp = {
      options = {
        icmpType = mkInvertibleOption types.oneOf [
          types.int
          (types.enum icmpTypesEnum)
        ];
      };
    };
  };

  moduleOptions = {config, ...}: {
    options = {
      module = mkOption {
        type = types.enum (attrNames moduleSettingsOptions);
        description = "";
      };
      options = mkOption {
        type = types.nullOr (types.submodule moduleSettingsOptions.${config.module} or {});
        default = null;
        description = "";
      };
    };
  };

  targetSettingsOptions = {
    balance = {
      options = {
        toDestination = mkOption {
          type = types.nonEmptyStr;
          description = "";
        };
      };
    };
    classify = {
      options = {};
    };
    clusterip = {
      options = {};
    };
    connmark = {
      options = {};
    };
    dnat = {
      options = {
        toDestination = mkOption {
          type = types.nonEmptyStr;
          description = "";
        };
      };
    };
    log = {
      options = {
        level = mkOption {
          type = types.nullOr types.int;
          description = "";
        };
        prefix = mkOption {
          type = types.nullOr types.nonEmptyStr;
          description = "";
        };
        tcpSequence = mkOption {
          type = types.nullOr types.bool;
          description = "";
        };
        tcpOptions = mkOption {
          type = types.nullOr types.bool;
          description = "";
        };
        ipOptions = mkOption {
          type = types.nullOr types.bool;
          description = "";
        };
        uid = mkOption {
          type = types.nullOr types.bool;
          description = "";
        };
      };
    };
    mark = {
      options = {
        mark = mkOption {
          type = types.nullOr (types.submodule {
            options = {
              value = mkOption {
                type = types.nonEmptyStr;
                description = "";
              };
              mask = mkOption {
                type = types.nullOr types.nonEmptyStr;
                default = null;
                description = "";
              };
            };
          });
          default = null;
          description = "";
        };
        xmark = mkOption {
          type = types.nullOr (types.submodule {
            options = {
              value = mkOption {
                type = types.nonEmptyStr;
                description = "";
              };
              mask = mkOption {
                type = types.nullOr types.nonEmptyStr;
                default = null;
                description = "";
              };
            };
          });
          default = null;
          description = "";
        };
        andMark = mkOption {
          type = types.nullOr types.nonEmptyStr;
          default = null;
          description = "";
        };
        orMark = mkOption {
          type = types.nullOr types.nonEmptyStr;
          default = null;
          description = "";
        };
        xorMark = mkOption {
          type = types.nullOr types.nonEmptyStr;
          default = null;
          description = "";
        };
      };
    };
    redirect = {
      options = {
        toPorts = mkOption {
          type = types.nullOr (types.either types.port (types.submodule portRangeOptions));
          default = null;
          description = "";
        };
        random = mkOption {
          type = types.nullOr types.bool;
          default = null;
          description = "";
        };
      };
    };
    snat = {
      options = {
        toSource = mkOption {
          type = types.nonEmptyStr;
          description = "";
        };
      };
    };
  };

  targetOptions = {config, ...}: {
    options = {
      module = mkOption {
        type = types.enum (attrNames targetSettingsOptions);
        description = "";
      };
      options = mkOption {
        type = types.nullOr (types.submodule targetSettingsOptions.${config.module} or {});
        default = null;
        description = "";
      };
    };
  };

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
    input = mkInvertibleOption (types.either types.nonEmptyStr (types.listOf types.nonEmptyStr));
    output = mkInvertibleOption (types.either types.nonEmptyStr (types.listOf types.nonEmptyStr));
    source = mkInvertibleOption (types.either types.nonEmptyStr (types.listOf types.nonEmptyStr));
    destination = mkInvertibleOption (types.either types.nonEmptyStr (types.listOf types.nonEmptyStr));
    protocol = mkOption {
      type = types.nullOr (types.oneOf [types.int (types.enum ["tcp" "udp" "vrrp" "ah"])]);
      description = "";
      default = null;
    };
    modules = mkOption {
      type = types.listOf (types.submodule moduleOptions);
      description = "";
      default = [];
    };
    extraArgs = mkOption {
      type = types.nullOr types.nonEmptyStr;
      description = "";
      default = null;
    };
    target = mkOption {
      type = types.either types.nonEmptyStr (types.submodule targetOptions);
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
        destinationPorts = mkInvertibleOption (types.listOf (types.either types.port (types.submodule portRangeOptions)));
      };
    config = {
      version = mkDefault "any";
      modules = [
        {
          module = "tcp";
        }
        {
          module = "multiport";
          options.destinationPorts = config.destinationPorts;
        }
      ];
    };
  };

  udpRuleModule = {config, ...}: {
    options =
      ruleOptions
      // {
        destinationPorts = mkInvertibleOption (types.listOf (types.either types.port (types.submodule portRangeOptions)));
      };
    config = {
      version = mkDefault "any";
      modules = [
        {
          module = "udp";
        }
        {
          module = "multiport";
          options.destinationPorts = config.destinationPorts;
        }
      ];
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
      extraArgs
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
in {
  options = {
    networking.firewall = {
      rules = {
        tcp = mkOption {
          type = types.listOf (types.submodule tcpRuleModule);
          default = [];
          description = "";
        };
        udp = mkOption {
          type = types.listOf (types.submodule udpRuleModule);
          default = [];
          description = "";
        };
        icmp = mkOption {
          type = types.listOf (types.submodule icmpRuleModule);
          default = [];
          description = "";
        };
        extra = mkOption {
          type = types.listOf (types.submodule ruleModule);
          default = [];
          description = "";
        };
      };
    };
  };
  config = {
    networking.firewall = {
      extraCommands = concatMapStringsSep "\n" (rule: mapRule rule true) rules;
      extraStopCommands = concatMapStringsSep "\n" (rule: "${mapRule rule false} || true") rules;
    };
  };
}
