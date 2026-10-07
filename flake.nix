{
  description = "redact: keep private values out of a public git repository";

  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = "1.0.0";
      package =
        pkgs:
        pkgs.buildGoModule {
          pname = "redact";
          inherit version;
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./go.mod
              ./go.sum
              ./cmd
              ./internal
            ];
          };
          vendorHash = "sha256-Is9kHfmv4a67Jkt/fjXGdZ87SiPfqg25g2J6qsPo9vM=";
          subPackages = [ "cmd/redact" ];
          env.CGO_ENABLED = 0;
          ldflags = [
            "-s"
            "-w"
            "-X github.com/scuba-plaza/redact/internal/cli.version=${version}"
          ];
          nativeCheckInputs = [ pkgs.git ];
          preCheck = ''
            unset subPackages
          '';
          nativeBuildInputs = [ pkgs.installShellFiles ];
          postInstall = pkgs.lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) ''
            installShellCompletion --cmd redact \
              --bash <($out/bin/redact completion bash) \
              --fish <($out/bin/redact completion fish) \
              --zsh <($out/bin/redact completion zsh)
          '';
          meta = {
            description = "Keep private values out of a public git repository while your working tree keeps them";
            mainProgram = "redact";
            platforms = pkgs.lib.platforms.unix;
          };
        };
    in
    {
      packages = forAllSystems (pkgs: rec {
        redact = package pkgs;
        default = redact;
      });

      overlays.default = final: prev: { redact = package final; };

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = pkgs.lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
      });

      checks = forAllSystems (pkgs: {
        redact = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.golangci-lint
            pkgs.git
            pkgs.age
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
