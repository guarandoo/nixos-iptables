# nixos-iptables

> ⚠️ WARNING: This is in very early stages and not all functionality is tested, use at your own risk, PRs to cover more options are welcome.

A declarative module for `iptables`.

## Usage

### Flakes

Add this repository as an input to your flake and import the module

```nix
{
  description = "My NixOS flake";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/unstable";
    # ...
    nixos-iptables.url = "github:guarandoo/nixos-iptables"; # add flake as input
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
          # ...
          nixos-iptables.nixosModules.default # add module
        ];
      }
    };
  }
}
```

## Examples

### Simple

#### Allow all inbound traffic on TCP ports 80 and 443

```nix
networking.firewall.rules.tcp = [
  # ip46tables -A nixos-firewall -m tcp -p tcp -m multiport --destination-ports 80,443 -j nixos-fw-accept -m --comment 'nginx'
  {
    destinationPorts = [80 443];
    comment = "nginx";
  }
];
```

#### Allow all inbound traffic on UDP port 53

```nix
networking.firewall.rules.udp = [
  # ip46tables -A nixos-firewall -m udp -p udp -m multiport --destination-ports 53 -j nixos-fw-accept -m --comment 'dns'
  {
    destinationPorts = [53];
    comment = "dns";
  }
];
```

#### Prevent traffic destined for RFC1918 addresses from leaving non-private interfaces

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
    comment = "drop bogons";
  }
];
```

### SNAT

#### Masquerade all traffic coming from container interfaces (ve-\*) leaving a certain outbound interface (ens3)

```nix
networking.firewall.rules.extra = [
  # ip46tables -t mangle -A PREROUTING -i ve-+ -j MARK --set-mark 0x01/0xff
  {
    version = "any";
    table = "mangle";
    chain = "PREROUTING";
    input = "ve-+";
    target = {
      module = "MARK";
      options.setMark = {
        value = "0x01";
        mask = "0xff";
      };
    };
  }
  # ip46tables -t mangle -A POSTROUTING -o ens3 -m mark --mark 0x01/0xff -j MASQUERADE
  {
    version = "any";
    table = "nat";
    chain = "POSTROUTING";
    output = "ens3";
    modules = [
      {
        module = "mark";
        options.mark = {
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

#### Forward TCP connections received on `192.168.0.1:2222` to `192.168.0.2:22`

```nix
networking.firewall.rules.extra = [
  # iptables -t nat -A PREROUTING -i ens18 -d 192.168.0.1 -p tcp --dport 2222 -j DNAT --to-destination 192.168.0.2:22
  {
    version = 4;
    table = "nat";
    chain = "PREROUTING";
    input = "ens18";
    destination = "192.168.0.1";
    modules = [
      {
        module = "tcp";
        options.destinationPort = 2222;
      }
    ];
    target = {
      module = "DNAT";
      options.toDestination = "192.168.0.2:22";
    };
  }
];
```

### Redirect

#### Redirect all UDP packets received on port `53` to port `5353`

```nix
networking.firewall.rules.extra = [
  # iptables -t nat -A PREROUTING -i ens18 -p udp --dport 53 -j REDIRECT --to-ports 5353
  {
    version = "any";
    table = "nat";
    chain = "PREROUTING";
    input = "ens18";
    modules = [
      {
        module = "udp";
        options.destinationPort = 53;
      }
    ];
    target = {
      module = "REDIRECT";
      options.toPorts = 5353;
    };
  }
];
```

#### Redirect TCP packets received on port `22` to port `2222`

The setup below is useful for redirecting ports only on certain destination addresses _(or interfaces)_.

It also prevents connections directly on the target port forcing packets to go through the redirect.

```nix
networking.firewall.rules = {
  extra = [
    # iptables -t mangle -I PREROUTING -d 1.1.1.1 -m tcp --dport 22 -j MARK --set-mark 0x02/0xff
    {
      version = 4;
      table = "mangle";
      chain = "PREROUTING";
      destination = [
        "1.1.1.1"
        "8.8.8.8"
      ];
      modules = [
        {
          module = "tcp";
          options.destinationPort = 22;
        }
      ];
      target = {
        module = "MARK";
        options.setMark = {
          value = "0x02";
          mask = "0xff";
        };
      };
    }
    # iptables -t nat -I PREROUTING -m mark --mark 0x02/0xff -m tcp --dport 22 -j REDIRECT --to-ports 2222
    {
      version = 4;
      table = "nat";
      chain = "PREROUTING";
      modules = [
        {
          module = "mark";
          options.mark = {
            value = "0x02";
            mask = "0xff";
          };
        }
        {
          module = "tcp";
          options.destinationPort = 22;
        }
      ];
      target = {
        module = "REDIRECT";
        options.toPorts = 2222;
      };
    }
  ];
  tcp = [
    # iptables -A nixos-fw -m tcp --dport 2222 -m mark --mark 0x02/0xff -j ACCEPT
    {
      destinationPorts = [2222];
      modules = [
        {
          module = "mark";
          options.mark = {
            value = "0x02";
            mask = "0xff";
          };
        }
      ];
    }
  ];
};
```

or alternatively, using the `conntrack` module

```nix
networking.firewall.rules = {
  extra = [
    # iptables -t nat -I PREROUTING -d 1.1.1.1,8.8.8.8 -m tcp --dport 22 -j REDIRECT --to-ports 2222
    {
      version = 4;
      table = "nat";
      chain = "PREROUTING";
      destination = [
        "1.1.1.1"
        "8.8.8.8"
      ];
      modules = [
        {
          module = "tcp";
          options.destinationPort = 22;
        }
      ];
      target = {
        module = "REDIRECT";
        options.toPorts = 2222;
      };
    }
  ];
  tcp = [
    # iptables -A nixos-fw -m tcp --dport 2222 -m conntrack --ctorigdstport 22 -j ACCEPT
    {
      destinationPorts = [2222];
      modules = [
        {
          module = "conntrack";
          options.ctorigdstport = 22;
        }
      ];
    }
  ];
};
```
