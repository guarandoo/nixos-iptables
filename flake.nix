{
  description = "A declarative module for iptables";
  outputs = {self, ...} @ inputs: {
    nixosModules = rec {
      nixos-iptables = import ./modules;
      default = nixos-iptables;
    };
  };
}
