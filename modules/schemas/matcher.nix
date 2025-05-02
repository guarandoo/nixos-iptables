{lib, ...}: let
  inherit (builtins) mapAttrs;
  inherit (lib) types mkOption;

  portRangeOptions = {
    options = {
      separator = mkOption {
        type = types.nonEmptyStr;
        default = ":";
        description = "";
      };
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

  customTypes = import ../types.nix {inherit lib;};

  schema = {
    # region addrtype
    addrtype = let
      addressTypes = [
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
    in {
      options = {
        # [!] --src-type type
        srcType = {
          name = "src-type";
          invertible = true;
          type = types.enum addressTypes;
        };
        # [!] --dst-type type
        dstType = {
          name = "dst-type";
          invertible = true;
          type = types.enum addressTypes;
        };
        # --limit-iface-in
        limitIfaceIn = {
          name = "limit-iface-in";
          flag = true;
          type = types.bool;
        };
        # --limit-iface-out
        limitIfaceOut = {
          name = "limit-iface-out";
          flag = true;
          type = types.bool;
        };
      };
    };
    # endregion
    # region ah6
    ah6 = {
      options = {
        # [!] --ahspi spi[:spi]
        ahspi = {
          name = "ahspi";
          invertible = true;
          types = customTypes.intOrIntRange;
        };
        # [!] --ahlen length
        ahlen = {
          name = "ahlen";
          invertible = true;
          type = types.int;
        };
        # --ahres
        ahres = {
          name = "ahres";
          flag = true;
          type = types.bool;
        };
      };
    };
    # endregion
    # region ah4
    ah4 = {
      options = {
        # [!] --ahspi spi[:spi]
        ahspi = {
          name = "ahspi";
          invertible = true;
          type = customTypes.intOrIntRange;
        };
      };
    };
    # endregion
    # region bpf
    bpf = {
      options = {
        # --object-pinned path
        objectPinned = {
          name = "object-pinned";
          type = types.nonEmptyStr;
        };
        # --bytecode code
        bytecode = {
          name = "bytecode";
          type = types.nonEmptyStr;
        };
      };
    };
    # endregion bpf
    # region cgroup
    cgroup = {
      options = {
        # [!] --path path
        path = {
          name = "path";
          invertible = true;
          type = types.nonEmptyStr;
        };
        # [!] --cgroup classid
        cgroup = {
          name = "classid";
          invertible = true;
          type = types.int;
        };
      };
    };
    # endregion
    # region cluster
    cluster = {
      options = {
        # --cluster-total-nodes num
        clusterTotalNodes = {
          name = "cluster-total-nodes";
          type = types.int;
        };
        # [!] --cluster-local-node num
        clusterLocalNode = {
          name = "cluster-local-node";
          invertible = true;
          type = types.int;
        };
        # [!] --cluster-local-nodemask mask
        cluster-local-nodemask = {
          name = "cluster-local-nodemask";
          invertible = true;
          type = types.nonEmptyStr;
        };
        # --cluster-hash-seed value
        clusterHashSeed = {
          name = "cluster-hash-seed";
          type = types.nonEmptyStr;
        };
      };
    };
    # endregion
    # region comment
    comment = {
      options = {
        comment = {
          name = "comment";
          type = types.nonEmptyStr;
        };
      };
    };
    # endregion
    # region connbytes
    connbytes = let
      direction = [
        "original"
        "reply"
        "both"
      ];
      mode = [
        "packets"
        "bytes"
        "avgpkt"
      ];
    in {
      options = {
        # [!] --connbytes from[:to]
        connbytes = {
          name = "connbytes";
          invertible = true;
          type = customTypes.intOrIntRange;
        };
        # --connbytes-dir {original|reply|both}
        connbytesDir = {
          name = "connbytes-dir";
          type = types.enum direction;
        };
        # --connbytes-mode {packets|bytes|avgpkt}
        connbytesMode = {
          name = "connbytes-mode";
          type = types.enum mode;
        };
      };
    };
    # endregion
    # region connlimit
    connlimit = {
      options = {
        # --connlimit-upto n
        connlimitUpto = {
          name = "connlimit-upto";
          type = types.int;
        };
        # --connlimit-above n
        connlimitAbove = {
          name = "connlimit-above";
          type = types.int;
        };
        # --connlimit-mask prefix_length
        connlimitMask = {
          name = "connlimit-mask";
          type = types.int;
        };
        # --connlimit-saddr
        connlimitSaddr = {
          name = "connlimit-saddr";
          flag = true;
          type = types.bool;
        };
        # --connlimit-daddr
        connlimitDaddr = {
          name = "connlimit-daddr";
          flag = true;
          type = types.bool;
        };
      };
    };
    # endregion
    # region connmark
    connmark = {
      options = {
        mark = {
          name = "mark";
          invertible = true;
          type = customTypes.stringValueWithOptionalStringMaskType;
        };
      };
    };
    # endregion
    # region conntrack
    conntrack = let
      stateEnum = [
        "INVALID"
        "NEW"
        "ESTABLISHED"
        "RELATED"
        "UNTRACKED"
        "SNAT"
        "DNAT"
      ];
      statusEnum = [
        "NONE"
        "EXPECTED"
        "SEEN_REPLY"
        "ASSURED"
        "CONFIRMED"
      ];
      dir = [
        "ORIGINAL"
        "REPLY"
      ];
    in {
      options = {
        # [!] --ctstate statelist
        ctstate = {
          name = "ctstate";
          invertible = true;
          type = types.either (types.enum stateEnum) (types.listOf (types.enum stateEnum));
        };
        # [!] --ctproto l4proto
        ctproto = {
          name = "ctproto";
          invertible = true;
          type = types.either types.nonEmptyStr types.int;
        };
        # [!] --ctorigsrc address[/mask]
        ctorigsrc = {
          name = "ctorigsrc";
          invertible = true;
          type = customTypes.stringValueWithOptionalStringMaskType;
        };
        # [!] --ctorigdst address[/mask]
        ctorigdst = {
          name = "ctorigdst";
          invertible = true;
          type = customTypes.stringValueWithOptionalStringMaskType;
        };
        # [!] --ctreplsrc address[/mask]
        ctreplsrc = {
          name = "ctreplsrc";
          invertible = true;
          type = customTypes.stringValueWithOptionalStringMaskType;
        };
        # [!] --ctrepldst address[/mask]
        ctrepldst = {
          name = "ctrepldst";
          invertible = true;
          type = customTypes.stringValueWithOptionalStringMaskType;
        };
        # [!] --ctorigsrcport port[:port]
        ctorigsrcport = {
          name = "ctorigsrcport";
          invertible = true;
          type = customTypes.portOrPortRange;
        };
        # [!] --ctorigdstport port[:port]
        ctorigdstport = {
          name = "ctorigdstport";
          invertible = true;
          type = customTypes.portOrPortRange;
        };
        # [!] --ctreplsrcport port[:port]
        ctreplsrcport = {
          name = "ctreplsrcport";
          invertible = true;
          type = customTypes.portOrPortRange;
        };
        # [!] --ctrepldstport port[:port]
        ctrepldstport = {
          name = "ctrepldstport";
          invertible = true;
          type = customTypes.portOrPortRange;
        };
        # [!] --ctstatus statelist
        ctstatus = {
          name = "ctstatus";
          invertible = true;
          type = types.enum statusEnum;
        };
        # [!] --ctexpire time[:time]
        ctexpire = {
          name = "ctexpire";
          invertible = true;
          type = customTypes.intOrIntRange;
        };
        # --ctdir {ORIGINAL|REPLY}
        ctdir = {
          name = "ctdir";
          type = types.enum dir;
        };
      };
    };
    # endregion
    # region cpu
    cpu = {
      options = {
        # [!] --cpu number
        cpu = {
          name = "cpu";
          invertible = true;
          type = types.int;
        };
      };
    };
    # endregion
    # region dccp
    dccp = let
      mask = [
        "REQUEST"
        "RESPONSE"
        "DATA"
        "ACK"
        "DATA"
        "DATAACK"
        "CLOSEREQ"
        "CLOSE"
        "RESET"
        "SYNC"
        "SYNCACK"
        "INVALID"
      ];
    in {
      options = {
        # [!] --source-port,--sport port[:port]
        sourcePort = {
          name = "source-port";
          aliases = ["sport"];
          invertible = true;
          type = customTypes.portOrPortRange;
        };
        # [!] --destination-port,--dport port[:port]
        destinationPort = {
          name = "destination-port";
          aliases = ["dport"];
          invertible = true;
          type = customTypes.portOrPortRange;
        };
        # [!] --dccp-types mask
        dccpTypes = {
          name = "dccp-types";
          invertible = true;
          type = types.either (types.enum mask) (types.listOf (types.enum mask));
        };
        # [!] --dccp-option number
        dccpOption = {
          name = "dccp-option";
          invertible = true;
          type = types.int;
        };
      };
    };
    # endregion
    # region devgroup
    devgroup = {
      options = {
        # [!] --src-group name
        srcGroup = {
          name = "src-group";
          invertible = true;
          type = types.nonEmptyStr;
        };
        # [!] --dst-group name
        dstGroup = {
          name = "dst-group";
          invertible = true;
          type = types.nonEmptyStr;
        };
      };
    };
    # endregion
    # region dscp
    dscp = {
      options = {
        # [!] --dscp value
        dscp = {
          name = "dscp";
          invertible = true;
          type = types.nonEmptyStr;
        };
        # [!] --dscp-class class
        dscp-class = {
          name = "dscp-class";
          invertible = true;
          type = types.nonEmptyStr;
        };
      };
    };
    # endregion
    # ... skip
    # region icmp
    icmp = {
      extraArgs = ["-p icmp"];
      options = {
        # [!] --icmp-type {type[/code]|typename}
        icmpType = {
          name = "icmp-type";
          invertible = true;
          type = types.nonEmptyStr; # TODO: could be better
        };
      };
    };
    # endregion
    # region icmp6
    icmp6 = {
      extraArgs = ["-p icmpv6"];
      options = {
        # [!] --icmpv6-type type[/code]|typename
        icmpv6Type = {
          name = "icmpv6-type";
          invertible = true;
          type = types.nonEmptyStr; # TODO: could be better
        };
      };
    };
    # endregion
    # region iprange
    iprange = {
      options = {
        # [!] --src-range from[-to]
        srcRange = {
          name = "src-range";
          invertible = true;
          type = customTypes.ipRange;
        };
        # [!] --dst-range from[-to]
        dstRange = {
          name = "dst-range";
          invertible = true;
          type = customTypes.ipRange;
        };
      };
    };
    # endregion
    # ... skip
    # region mark
    mark = {
      options = {
        mark = {
          name = "mark";
          invertible = true;
          type = customTypes.stringValueWithOptionalStringMaskType;
        };
      };
    };
    # endregion
    # region multiport
    multiport = {
      options = {
        sourcePorts = {
          name = "source-ports";
          aliases = ["sports"];
          invertible = true;
          type = types.oneOf [
            types.port
            (types.submodule portRangeOptions)
            (types.listOf (types.either types.port (types.submodule portRangeOptions)))
          ];
        };
        destinationPorts = {
          name = "destination-ports";
          aliases = ["sports"];
          invertible = true;
          type = types.oneOf [
            types.port
            (types.submodule portRangeOptions)
            (types.listOf (types.either types.port (types.submodule portRangeOptions)))
          ];
        };
        ports = {
          name = "ports";
          invertible = true;
          type = types.oneOf [
            types.port
            (types.submodule portRangeOptions)
            (types.listOf (types.either types.port (types.submodule portRangeOptions)))
          ];
        };
      };
    };
    # endregion
    # ... skip
    # region state
    state = let
      state = [
        "INVALID"
        "ESTABLISHED"
        "NEW"
        "RELATED"
        "UNTRACKED"
      ];
    in {
      options = {
        # [!] --state state
        state = {
          name = "state";
          invertible = true;
          type = types.either (types.enum state) (types.listOf (types.enum state));
        };
      };
    };
    # endregion
    # ... skip
    # region tcp
    tcp = let
      flags = [
        "SYN"
        "ACK"
        "FIN"
        "RST"
        "URG"
        "PSH"
        "ALL"
        "NONE"
      ];
    in {
      extraArgs = ["-p tcp"];
      options = {
        # [!] --source-port,--sport port[:port]
        sourcePort = {
          name = "source-port";
          aliases = ["sport"];
          invertible = true;
          type = types.oneOf [types.port (types.submodule portRangeOptions)];
        };
        # [!] --destination-port,--dport port[:port]
        destinationPort = {
          name = "destination-port";
          aliases = ["dport"];
          invertible = true;
          type = types.oneOf [types.port (types.submodule portRangeOptions)];
        };
        # [!] --tcp-flags mask comp
        tcpFlags = {
          name = "tcp-flags";
          invertible = true;
          type = types.nonEmptyStr; # TODO: handle nested/2 parameters
        };
        # [!] --syn
        syn = {
          name = "syn";
          invertible = true;
          type = types.bool;
        };
        # [!] --tcp-option number
        tcpOption = {
          name = "tcp-option";
          invertible = true;
          type = types.int;
        };
      };
    };
    # endregion
    # ... skip
    # region udp
    udp = {
      extraArgs = ["-p udp"];
      options = {
        # [!] --source-port,--sport port[:port]
        sourcePort = {
          name = "source-port";
          aliases = ["sport"];
          invertible = true;
          type = customTypes.portOrPortRange;
        };
        # [!] --destination-port,--dport port[:port]
        destinationPort = {
          name = "destination-port";
          aliases = ["dport"];
          invertible = true;
          type = customTypes.portOrPortRange;
        };
      };
    };
    # endregion
  };

  optionDefaults = name: {
    aliases = [];
    prefix = "--";
    inherit name;
    invertible = false;
    flag = false;
  };
in
  mapAttrs (k: v: v // {options = mapAttrs (k: v: (optionDefaults k) // v) v.options;}) schema
