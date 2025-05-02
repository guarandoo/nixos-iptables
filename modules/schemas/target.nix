{lib, ...}: let
  inherit (builtins) mapAttrs;
  inherit (lib) types;

  customTypes = import ../types.nix {inherit lib;};

  schema = {
    # region DNAT
    DNAT = {
      options = {
        toDestination = {
          name = "to-destination";
          type = types.nonEmptyStr; # TODO: could be better
        };
        random = {
          name = "random";
          flag = true;
          type = types.bool;
        };
        persistent = {
          name = "persistent";
          flag = true;
          type = types.bool;
        };
      };
    };
    # endregion
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
