{lib, ...}: let
  inherit (builtins) mapAttrs;
  inherit (lib) types mkOption;

  customTypes = import ../types.nix {inherit lib;};

  # https://ipset.netfilter.org/iptables-extensions.man.html
  schema = {
    # region AUDIT
    AUDIT = let
      typeValues = [
        "accept"
        "drop"
        "reject"
      ];
    in {
      options = {
        # --type {accept|drop|reject}
        type = {
          name = "type";
          type = types.enum typeValues;
          description = "Set type of audit record. Starting with linux-4.12, this option has no effect on generated audit messages anymore. It is still accepted by iptables for compatibility reasons, but ignored.";
        };
      };
    };
    # endregion
    # region CHECKSUM
    CHECKSUM = {
      options = {
        # --checksum-fill
        checksumFill = {
          name = "checksum-fill";
          flag = true;
          type = types.bool;
          description = "Compute and fill in the checksum in a packet that lacks a checksum. This is particularly useful, if you need to work around old applications such as dhcp clients, that do not work well with checksum offloads, but don't want to disable checksum offload in your device.";
        };
      };
    };
    # endregion
    # region CLASSIFY
    CLASSIFY = {
      options = {
        # --set-class major:minor
        setClass = {
          name = "set-class";
          type = types.submodule {
            options = {
              major = mkOption {
                type = types.int;
                description = "";
              };
              minor = mkOption {
                type = types.int;
                description = "";
              };
            };
          };
          description = "Set the major and minor class value. The values are always interpreted as hexadecimal even if no 0x prefix is given.";
        };
      };
    };
    # endregion
    # region CLUSTERIP
    CLUSTERIP = let
      hashmodeValues = [
        "sourceip"
        "sourceip-sourceport"
        "sourceip-sourceport-destport"
      ];
    in {
      options = {
        # --new
        new = {
          name = "new";
          flag = true;
          type = types.bool;
          description = "Create a new ClusterIP. You always have to set this on the first rule for a given ClusterIP.";
        };
        # --hashmode mode
        hashmode = {
          name = "hashmode";
          type = types.enum hashmodeValues;
          description = "Specify the hashing mode. Has to be one of sourceip, sourceip-sourceport, sourceip-sourceport-destport.";
        };
        # --clustermac mac
        clustermac = {
          name = "clustermac";
          type = types.nonEmptyStr;
          description = "Specify the ClusterIP MAC address. Has to be a link-layer multicast address";
        };
        # --total-nodes num
        totalNodes = {
          type = types.int;
          description = "Number of total nodes within this cluster.";
        };
        # --local-node num
        localNode = {
          type = types.int;
          description = "Local node number within this cluster.";
        };
        # --hash-init rnd
        hashInit = {
          type = types.nonEmptyStr;
          description = "Specify the random seed used for hash initialization.";
        };
      };
    };
    # endregion
    # region CONNMARK
    CONNMARK = {
      options = {
        # --set-xmark value[/mask]
        setXmark = {
          name = "set-xmark";
          type = customTypes.stringValueWithOptionalStringMaskType;
          description = "Zero out the bits given by mask and XOR value into the ctmark.";
        };
        # --save-mark [--nfmask nfmask] [--ctmask ctmask]
        # saveMark = {
        #   name = "save-mark";
        #   type = types.bool;
        #   description = ''
        #     Copy the packet mark (nfmark) to the connection mark (ctmark) using the given masks. The new nfmark value is determined as follows:
        #     ctmark = (ctmark & ~ctmask) ^ (nfmark & nfmask)
        #     i.e. ctmask defines what bits to clear and nfmask what bits of the nfmark to XOR into the ctmark. ctmask and nfmask default to 0xFFFFFFFF.
        #   '';
        # };
        # --restore-mark [--nfmask nfmask] [--ctmask ctmask]
        # restoreMark = {
        #   name = "restore-mark";
        #   type = types.bool;
        #   description = ''
        #     Copy the connection mark (ctmark) to the packet mark (nfmark) using the given masks. The new ctmark value is determined as follows:
        #     nfmark = (nfmark & ~nfmask) ^ (ctmark & ctmask);
        #     i.e. nfmask defines what bits to clear and ctmask what bits of the ctmark to XOR into the nfmark. ctmask and nfmask default to 0xFFFFFFFF.
        #     --restore-mark is only valid in the mangle table.
        #   '';
        # };
        # --and-mark bits
        andMark = {
          name = "and-mark";
          type = types.nonEmptyStr;
          description = "Binary AND the ctmark with bits. (Mnemonic for --set-xmark 0/invbits, where invbits is the binary negation of bits.)";
        };
        # --or-mark bits
        orMark = {
          name = "or-mark";
          type = types.nonEmptyStr;
          description = "Binary OR the ctmark with bits. (Mnemonic for --set-xmark bits/bits.)";
        };
        # --xor-mark bits
        xorMark = {
          name = "xor-mark";
          type = types.nonEmptyStr;
          description = "Binary XOR the ctmark with bits. (Mnemonic for --set-xmark bits/0.)";
        };
        # --set-mark value[/mask]
        setMark = {
          name = "set-mark";
          type = customTypes.stringValueWithOptionalStringMaskType;
          description = "Set the connection mark. If a mask is specified then only those bits set in the mask are modified.";
        };
      };
    };
    # endregion
    # region CONNSECMARK
    CONNSECMARK = {
      options = {
        # --save
        save = {
          name = "save";
          flag = true;
          type = types.bool;
          description = "If the packet has a security marking, copy it to the connection if the connection is not marked.";
        };
        # --restore
        restore = {
          name = "restore";
          flag = true;
          type = types.bool;
          description = "If the packet does not have a security marking, and the connection does, copy the security marking from the connection to the packet.";
        };
      };
    };
    # endregion
    # region CT
    CT = {
      options = {
        # --notrack
        notrack = {
          name = "notrack";
          flag = true;
          type = types.bool;
          description = "Disables connection tracking for this packet.";
        };
        # --helper name
        helper = {
          name = "helper";
          type = types.nonEmptyStr;
          description = "Use the helper identified by name for the connection. This is more flexible than loading the conntrack helper modules with preset ports.";
        };
        # --ctevents event[,...]
        # ctevents = {
        #   name = "ctevents";
        #   description = "Only generate the specified conntrack events for this connection. Possible event types are: new, related, destroy, reply, assured, protoinfo, helper, mark (this refers to the ctmark, not nfmark), natseqinfo, secmark (ctsecmark).";
        # };
        # --expevents event[,...]
        # expevents = {
        #   name = "expevents";
        #   description = "Only generate the specified expectation events for this connection. Possible event types are: new.";
        # };
        # --zone-orig {id|mark}
        # zoneOrig = {
        #   name = "zone-orig";
        #   description = "For traffic coming from ORIGINAL direction, assign this packet to zone id and only have lookups done in that zone. If mark is used instead of id, the zone is derived from the packet nfmark.";
        # };
        # --zone-reply {id|mark}
        # zoneReply = {
        #   name = "zone-reply";
        #   description = "For traffic coming from REPLY direction, assign this packet to zone id and only have lookups done in that zone. If mark is used instead of id, the zone is derived from the packet nfmark.";
        # };
        # --zone {id|mark}
        # zone = {
        #   name = "zone";
        #   description = "Assign this packet to zone id and only have lookups done in that zone. If mark is used instead of id, the zone is derived from the packet nfmark. By default, packets have zone 0. This option applies to both directions.";
        # };
        # --timeout name
        timeout = {
          name = "timeout";
          type = types.nonEmptyStr;
          description = "Use the timeout policy identified by name for the connection. This is provides more flexible timeout policy definition than global timeout values available at /proc/sys/net/netfilter/nf_conntrack_*_timeout_*.";
        };
      };
    };
    # endregion
    # region DNAT
    DNAT = {
      options = {
        # --to-destination [ipaddr[-ipaddr]][:port[-port]]
        toDestination = {
          name = "to-destination";
          type = types.nonEmptyStr; # TODO: could be better
          description = ''
            which can specify a single new destination IP address, an inclusive range of IP addresses. Optionally a port range, if the rule also specifies one of the following protocols: tcp, udp, dccp or sctp. If no port range is specified, then the destination port will never be modified. If no IP address is specified then only the destination port will be modified. In Kernels up to 2.6.10 you can add several --to-destination options. For those kernels, if you specify more than one destination address, either via an address range or multiple --to-destination options, a simple round-robin (one after another in cycle) load balancing takes place between these addresses. Later Kernels (>= 2.6.11-rc1) don't have the ability to NAT to multiple ranges anymore.
          '';
        };
        # --random
        random = {
          name = "random";
          flag = true;
          type = types.bool;
          description = "If option --random is used then port mapping will be randomized (kernel >= 2.6.22).";
        };
        # --persistent
        persistent = {
          name = "persistent";
          flag = true;
          type = types.bool;
          description = "Gives a client the same source-/destination-address for each connection. This supersedes the SAME target. Support for persistent mappings is available from 2.6.29-rc2.";
        };
      };
    };
    # endregion
    # ... skip
    # region MARK
    MARK = {
      options = {
        setXmark = {
          name = "set-xmark";
          type = customTypes.stringValueWithOptionalStringMaskType;
        };
        setMark = {
          name = "set-mark";
          type = customTypes.stringValueWithOptionalStringMaskType;
        };
        andMark = {
          name = "and-mark";
          type = types.nonEmptyStr; # TODO: unsure about this one
        };
        orMark = {
          name = "or-mark";
          type = types.nonEmptyStr; # TODO: unsure about this one
        };
        xorMark = {
          name = "xor-mark";
          type = types.nonEmptyStr; # TODO: unsure about this one
        };
      };
    };
    # endregion
    # region MASQUERADE
    MASQUERADE = {
      options = {
        toPorts = {
          name = "to-ports";
          type = customTypes.valueOrValueRangeType "-" types.port;
        };
        random = {
          name = "random";
          flag = true;
          type = types.bool;
        };
        randomFully = {
          name = "random-fully";
          flag = true;
          type = types.bool;
        };
      };
    };
    # endregion
    # ... skip
    # region REDIRECT
    REDIRECT = {
      options = {
        toPorts = {
          name = "to-ports";
          type = customTypes.valueOrValueRangeType "-" types.port;
        };
        random = {
          name = "random";
          flag = true;
          type = types.bool;
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
