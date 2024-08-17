# nixos-iptables

#### WARNING: This is in very early stages and not all functionality is tested, use at your own risk, PRs to cover more options are welcome.

A declarative module for `iptables`.

## Usage

### Flakes

Add this repository as an input to your flake and import the module

```nix
{
  description = "My NixOS flake";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/unstable";
    nixos-iptables.url = "github:guarandoo/nixos-iptables/nixos-23.11"; # add flake as input
    # ...
  };
  outputs = {
    nixpkgs,
    nixos-iptables,
    ...
  }: {
    nixosConfigurations = {
      my-nixos-system = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          nixos-iptables.nixosModules.default # add module
          # ...
        ];
      }
    };
  }
}
```

## Examples

### Simple

Allow all inbound traffic on TCP ports 80 and 443

```nix
networking.firewall.rules.tcp = [
  # ip46tables -I nixos-firewall -m tcp -p tcp -m multiport --destination-ports 80,443 -j nixos-fw-accept -m --comment 'nginx'
  {
    ports = [80 443];
    description = "nginx";
  }
];
```

Prevent traffic destined for RFC1918 addresses from leaving non-private interfaces

```nix
networking.firewall.rules.extra = [
  # iptables -A nixos-fw -d 192.168.0.0/16,172.16.0.0/12,10.0.0.0/8 ! -o ens3 -j nixos-fw-refuse -m --comment 'drop bogons'
  {
    version = 4;
    destination = [
      "192.168.0.0/16"
      "172.16.0.0/12"
      "10.0.0.0/8"
    ];
    output = {
      invert = true;
      value = "ens3";
    };
    description = "drop bogons";
  }
];
```

### SNAT

Masquerade all traffic coming from container interfaces (ve-*) leaving a certain outbound interface (ens3)

```nix
networking.firewall.rules.extra = [
  # ip46tables -t mangle -A PREROUTING -i ve-+ -m mark --set-mark 0x01/0xff
  {
    version = "any";
    table = "mangle";
    chain = "PREROUTING";
    input = "ve-+";
    target = {
      module = "mark";
      options.mark = {
        value = "0x01";
        mask = "0xff";
      };
    };
  }
  # ip46tables -t mangle -A POSTROUTING -o ens3 -m mark --mark 0x01/0xff
  {
    version = "any";
    table = "nat";
    chain = "POSTROUTING";
    output = "ens3";
    modules = [
      {
        module = "mark";
        options = {
          value = "0x01";
          mask = "0xff";
        };
      }
    ];
    target = "MASQUERADE";
  }
];
```

### DNAT

Forward TCP connections received on `192.168.0.1:22` to `192.168.0.2:2222`

```nix
networking.firewall.rules.extra = [
  {
    version = 4;
    table = "nat";
    chain = "PREROUTING";
    input = "ens18";
    destination = "192.168.0.1";
    modules = [
      {
        module = "tcp";
        options.destinationPort = 22;
      }
    ];
    target = {
      module = "dnat";
      options.toDestination = "192.168.0.2:2222";
    };
  }
];
```