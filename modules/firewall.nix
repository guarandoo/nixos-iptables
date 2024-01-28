{
  lib,
  config,
  ...
}: let
  inherit
    (builtins)
    isList
    isAttrs
    attrNames
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

  isNotNullAndTrue = value: !isNull value && value;

  mapPortValue = value:
    if isList value
    then concatMapStringsSep "," mapPortValue value
    else if isAttrs value
    then "${toString value.start}:${toString value.end}"
    else toString value;

  mapModuleOptions = module: options: let
    mapOpts = {
      addrtype = options:
        optional (!isNull options) [
          (optional (!isNull options.srcType) "${optionalString (isNotNullAndTrue options.srcType.invert) "!"} --src-type ${options.srcType.type}")
          (optional (!isNull options.dstType) "${optionalString (isNotNullAndTrue options.srcType.invert) "!"} --dst-type ${options.dstType.type}")
          (optional (!isNull options.limitIfaceIn) "--limit-iface-in")
          (optional (!isNull options.limitIfaceOut) "--limit-iface-out")
        ];
      tcp = options:
        ["-p tcp"]
        ++ (optional (!isNull options) [
          (optional (!isNull options.sourcePort) "--source-port ${toString options.sourcePort}")
          (optional (!isNull options.destinationPort) "--destination-port ${toString options.destinationPort}")
        ]);
      udp = options:
        ["-p udp"]
        ++ (optional (!isNull options) [
          (optional (!isNull options.sourcePort) "--source-port ${toString options.sourcePort}")
          (optional (!isNull options.destinationPort) "--destination-port ${toString options.destinationPort}")
        ]);
      icmp = options:
        ["-p icmp"]
        ++ (optional (!isNull options [
          (optional (!isNull options.icmpType) "${optionalString (isNotNullAndTrue options.icmpType.invert) "!"} --icmp-type ${options.icmpType.type}")
        ]));
      multiport = options:
        optional (!isNull options) [
          (optional (!isNull options.sourcePorts) "${optionalString (isNotNullAndTrue options.sourcePorts.invert) "!"} --source-ports ${mapPortValue options.sourcePorts.ports}")
          (optional (!isNull options.destinationPorts) "${optionalString (isNotNullAndTrue options.destinationPorts.invert) "!"} --destination-ports ${mapPortValue options.destinationPorts.ports}")
          (optional (!isNull options.ports) "${optionalString (isNotNullAndTrue options.ports.invert) "!"} --ports ${mapPortValue options.ports.ports}")
        ];
      mark = options:
        optional (!isNull options) [
          "--mark ${options.value}${optionalString (!isNull options.mask) "/${options.mask}"}"
        ];
    };
    fn = mapOpts.${module};
  in
    concatStringsSep " " (flatten (fn options));

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
    if builtins.isString target
    then target
    else (concatStringsSep " " (flatten (fn target.options)));

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
      (optional (!isNull rule.input) "-i ${rule.input}")
      (optional (!isNull rule.output) "-o ${rule.output}")
      (optional (!isNull rule.source) "-s ${
        if builtins.isList rule.source
        then concatStringsSep "," rule.source
        else rule.source
      }")
      (optional (!isNull rule.destination) "-d ${rule.destination}")
      (optional (!isNull rule.protocol) "-p ${rule.protocol}")
      (concatMapStringsSep " " (module: "-m ${module.module}  ${mapModuleOptions module.module module.options}") rule.modules)
      (optional (!isNull rule.target) "-j ${mapTargetOptions rule.target}")
      (optional (!isNull rule.goto) "-g ${rule.goto}")
      (optional (!isNull rule.comment) "-m comment --comment ${lib.escapeShellArg rule.comment}")
      (optional (!isNull rule.extraArgs) rule.extraArgs)
    ]);

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

  moduleSettingsOptions = {
    addrtype = {
      options = {
        srcType = mkOption {
          type = types.submodule {
            options = {
              invert = mkOption {
                type = types.nullOr types.bool;
                default = null;
                description = "";
              };
              type = mkOption {
                type = types.enum addrTypesEnum;
                description = "";
              };
            };
          };
          default = null;
          description = "";
        };
        dstType = {
          type = types.submodule {
            options = {
              invert = mkOption {
                type = types.nullOr types.bool;
                default = null;
                description = "";
              };
              type = mkOption {
                type = types.enum addrTypesEnum;
                description = "";
              };
            };
            default = null;
            description = "";
          };
        };
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
        sourcePorts = mkOption {
          type = types.nullOr (types.submodule {
            options = {
              invert = mkOption {
                type = types.nullOr types.bool;
                default = null;
                description = "";
              };
              ports = mkOption {
                type = types.oneOf [
                  types.port
                  (types.submodule portRangeOptions)
                  (types.listOf (types.either types.port (types.submodule portRangeOptions)))
                ];
                description = "";
              };
            };
          });
          default = null;
          description = "";
        };
        destinationPorts = mkOption {
          type = types.nullOr (types.submodule {
            options = {
              invert = mkOption {
                type = types.nullOr types.bool;
                default = null;
                description = "";
              };
              ports = mkOption {
                type = types.oneOf [
                  types.port
                  (types.submodule portRangeOptions)
                  (types.listOf (types.either types.port (types.submodule portRangeOptions)))
                ];
                description = "";
              };
            };
          });
          default = null;
          description = "";
        };
        ports = mkOption {
          type = types.nullOr (types.submodule {
            options = {
              invert = mkOption {
                type = types.nullOr types.bool;
                default = null;
                description = "";
              };
              ports = mkOption {
                type = types.oneOf [
                  types.port
                  (types.submodule portRangeOptions)
                  (types.listOf (types.either types.port (types.submodule portRangeOptions)))
                ];
                description = "";
              };
            };
          });
          default = null;
          description = "";
        };
      };
    };
    tcp = {
      options = {
        sourcePort = mkOption {
          type = types.nullOr types.port;
          default = null;
          description = "";
        };
        destinationPort = mkOption {
          type = types.nullOr types.port;
          default = null;
          description = "";
        };
        tcpFlags = {
          invert = mkOption {
            type = types.bool;
            default = false;
            description = "";
          };
          flags = mkOption {
            type = types.nullOr (types.listOf (types.enum [
              "SYN"
              "ACK"
              "FIN"
              "RST"
              "URG"
              "PSH"
              "ALL"
              "NONE"
            ]));
            description = "";
            default = null;
          };
        };
        syn = mkOption {
          type = types.nullOr types.bool;
          description = "";
          default = null;
        };
      };
    };
    udp = {
      options = {
        sourcePort = mkOption {
          type = types.nullOr types.port;
          description = "";
          default = null;
        };
        destinationPort = mkOption {
          type = types.nullOr types.port;
          description = "";
          default = null;
        };
      };
    };
    mark = {
      options = {
        invert = mkOption {
          type = types.bool;
          default = false;
          description = "";
        };
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
    };
    icmp = {
      options = {
        icmpType = {
          invert = mkOption {
            type = types.bool;
            default = false;
            description = "";
          };
          type = mkOption {
            type = types.oneOf [
              types.int
              (types.enum icmpTypesEnum)
            ];
            description = "";
          };
        };
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
      options = {
      };
    };
    clusterip = {
      options = {
      };
    };
    connmark = {
      options = {
      };
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
    input = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = "";
    };
    output = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = "";
    };
    source = mkOption {
      type = types.nullOr (types.oneOf [types.nonEmptyStr (types.listOf types.nonEmptyStr)]);
      default = null;
      description = "";
    };
    destination = mkOption {
      type = types.nullOr types.nonEmptyStr;
      description = "";
      default = null;
    };
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
        destinationPorts = mkOption {
          type = types.listOf (types.either types.port (types.submodule portRangeOptions));
          description = "";
        };
      };
    config = {
      version = mkDefault "any";
      modules = [
        {
          module = "tcp";
        }
        {
          module = "multiport";
          options.destinationPorts.ports = config.destinationPorts;
        }
      ];
    };
  };

  udpRuleModule = {config, ...}: {
    options =
      ruleOptions
      // {
        destinationPorts = mkOption {
          type = types.listOf (types.either types.port (types.submodule portRangeOptions));
          description = "";
        };
      };
    config = {
      version = mkDefault "any";
      modules = [
        {
          module = "udp";
        }
        {
          module = "multiport";
          options.destinationPorts.ports = config.destinationPorts;
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
    cfg.rules.extra
    ++ (map (toRule "tcp") cfg.rules.tcp)
    ++ (map (toRule "udp") cfg.rules.udp)
    ++ (map (toRule "icmp") cfg.rules.icmp);
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
